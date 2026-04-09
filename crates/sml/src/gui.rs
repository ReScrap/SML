use std::{cell::LazyCell, collections::VecDeque, ffi::c_char, sync::OnceLock};

use crate::{hooks, lua, rva};
use eframe::{
    EventLoopBuilder,
    egui::{self, Color32},
};
use lua::S_LUA;
use sml_hook_macros::hook;
use sml_types::CStrDisp;
use tracing::{info, instrument};

use crossbeam_channel::{Receiver, Sender, unbounded};

#[derive(Debug, Eq, PartialEq)]
enum Syntax {
    Lua,
    Python,
}

impl std::fmt::Display for Syntax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lua => write!(f, "Lua"),
            Self::Python => write!(f, "Python"),
        }
    }
}

// TODO: fix python multiline input

#[derive(Debug, Eq, PartialEq)]
enum ConsoleMode {
    Console,
    RenderConsole,
}

impl std::fmt::Display for ConsoleMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Console => write!(f, "Console"),
            Self::RenderConsole => write!(f, "Render Console"),
        }
    }
}

#[derive(Debug)]
struct ScraplandEditor {
    code: String,
    command: String,
    syntax: Syntax,
    console: ConsoleMode,
    rx_con: Receiver<(u32, String)>,
    rx_rcon: Receiver<String>,
    log: Vec<(u32, String)>,
    rcon: Vec<String>,
}

impl ScraplandEditor {
    fn new(
        cc: &eframe::CreationContext<'_>,
        rx_con: Receiver<(u32, String)>,
        rx_rcon: Receiver<String>,
    ) -> Self {
        Self {
            code: String::new(),
            command: String::new(),
            syntax: Syntax::Python,
            console: ConsoleMode::Console,
            rx_con,
            rx_rcon,
            log: vec![],
            rcon: vec![],
        }
    }
}

impl ScraplandEditor {
    fn editor(&mut self, ui: &mut eframe::egui::Ui) {
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.syntax, Syntax::Python, "Python");
            ui.radio_value(&mut self.syntax, Syntax::Lua, "Lua");
        });
        let theme = egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());
        let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, wrap_width: f32| {
            let mut layout_job = egui_extras::syntax_highlighting::highlight(
                ui.ctx(),
                ui.style(),
                &theme,
                buf.as_str(),
                &self.syntax.to_string(),
            );
            layout_job.wrap.max_width = wrap_width;
            ui.fonts_mut(|f| f.layout_job(layout_job))
        };

        // No `let h = available_height() * 0.5` — let it fill.
        egui::ScrollArea::vertical()
            .id_salt("Edit")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let editor = egui::TextEdit::multiline(&mut self.code)
                    .font(egui::TextStyle::Monospace)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .layouter(&mut layouter);

                let _ = egui::CompletionPopup::new(ui.make_persistent_id("python_editor"))
                    .word_boundary(|c: char| !c.is_alphanumeric() && c != '_')
                    .max_height(150.0)
                    .show(ui, editor, |_query| vec![]);
            });

        if ui.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::Enter)) {
            match self.syntax {
                Syntax::Lua => {
                    let state = crate::lua::S_LUA.read();
                    match state.run(&self.code).and_then(|r| r.to_string()) {
                        Ok(res) => hooks::cprint(0x0000ff, &format!("[Lua] {res}\n")),
                        Err(err) => hooks::cprint(0xff0000, &format!("[Lua] {err}\n")),
                    }
                }
                Syntax::Python => hooks::python(&self.code),
            }
        }
    }
    fn console(&mut self, ui: &mut eframe::egui::Ui) {
        // Mode selector
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.console, ConsoleMode::Console, "Console");
            ui.radio_value(&mut self.console, ConsoleMode::RenderConsole, "Rencer");
        });

        // Input row pinned to the bottom — its height is reserved for us.
        egui::Panel::bottom("ConsoleInput").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(">")
                        .monospace()
                        .color(egui::Color32::LIGHT_GREEN),
                );
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.command)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .hint_text("Enter command…"),
                );
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if !self.command.is_empty() {
                        match self.console {
                            ConsoleMode::Console => hooks::cmd(&self.command),
                            ConsoleMode::RenderConsole => hooks::render(&self.command),
                        }
                        self.command.clear();
                    }
                    resp.request_focus();
                }
            });
        });

        // Build the log job.
        let font_id = egui::TextStyle::Monospace.resolve(ui.style());
        let mut job = egui::text::LayoutJob::default();
        match self.console {
            ConsoleMode::Console => {
                for (col, msg) in &self.log {
                    let [r, g, b, _] = col.to_le_bytes();
                    let m = 0.5;
                    let c = Color32::from_rgb(
                        (r as f32 * (1.0 - m) + 255.0 * m) as u8,
                        (g as f32 * (1.0 - m) + 255.0 * m) as u8,
                        (b as f32 * (1.0 - m) + 255.0 * m) as u8,
                    );
                    job.append(
                        msg,
                        0.0,
                        egui::TextFormat {
                            font_id: font_id.clone(),
                            color: c,
                            ..Default::default()
                        },
                    );
                }
            }
            ConsoleMode::RenderConsole => {
                let format = egui::TextFormat {
                    font_id: font_id.clone(),
                    ..Default::default()
                };
                for msg in &self.rcon {
                    job.append(msg, 0.0, format.clone());
                }
            }
        }

        // No max_height, no manual reserve — fills what's between combo and input.
        egui::ScrollArea::vertical()
            .id_salt("Console")
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| ui.label(job));
    }
}

impl eframe::App for ScraplandEditor {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let before = self.log.len();
        self.log.extend(self.rx_con.try_iter());
        if self.log.len() != before {
            ctx.request_repaint();
        }
        let before = self.rcon.len();
        self.rcon.extend(self.rx_rcon.try_iter());
        if self.rcon.len() != before {
            ctx.request_repaint();
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn ui(&mut self, ui: &mut eframe::egui::Ui, frame: &mut eframe::Frame) {
        // Cap the console so the editor always keeps the rest.
        let max_console = (ui.available_height() * 0.6).max(120.0);

        egui::Panel::bottom("Console")
            .resizable(true)
            .default_size(220.0)
            .min_size(120.0)
            .max_size(max_console) // <- the important bit
            .show(ui, |ui| self.console(ui));

        // Editor fills whatever is left (CentralPanel takes remaining space)
        egui::CentralPanel::default().show(ui, |ui| self.editor(ui));
    }
}

static CONSOLE: OnceLock<(Sender<(u32, String)>, Sender<String>)> = OnceLock::new();

#[hook(0x20eac0, C)]
fn console_log(msg: CStrDisp, color: u32) {
    if let Some((tx, _)) = CONSOLE.get() {
        let msg = msg.to_string();
        if !msg.is_empty() {
            let _ = tx.send((color, msg));
        }
    }
    original(msg, color)
}

#[allow(unused_variables)]
#[hook(0x2394d0, cdecl)] // 0x006394d0 - image base
unsafe fn rcon_log(
    fmt: *const c_char,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
    a12: usize,
    a13: usize,
    a14: usize,
    a15: usize,
) {
    type VFormat = unsafe extern "cdecl" fn(*mut c_char, usize, *const c_char, *const usize) -> i32;
    if fmt.is_null() {
        return;
    }

    // Rebuild a contiguous "va_list" (a pointer to the args on x86 MSVC).
    let va = [
        a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15,
    ];

    let vformat: VFormat = std::mem::transmute(rva::<()>(0x239f30));

    let mut buf = [0 as c_char; 1024];
    unsafe { vformat(buf.as_mut_ptr(), buf.len() - 1, fmt, va.as_ptr()) };
    buf[1023] = 0;

    if let Some((_, tx)) = CONSOLE.get() {
        let msg = CStrDisp::from_ptr(buf.as_ptr()).to_string();
        let _ = tx.send(msg);
    }

    unsafe {
        original(
            c"%s".as_ptr(),
            buf.as_ptr() as usize,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    };
}

pub(crate) fn spawn() {
    let (tx_con, rx_con) = unbounded();
    let (tx_rcon, rx_rcon) = unbounded();
    let _ = CONSOLE.set((tx_con, tx_rcon));
    use winit::platform::windows::EventLoopBuilderExtWindows;
    std::thread::spawn(move || {
        let native_options = eframe::NativeOptions {
            event_loop_builder: Some(Box::new(|ebh| {
                ebh.with_any_thread(true);
            })),
            ..Default::default()
        };
        let _ = eframe::run_native(
            "Scrapland Console",
            native_options,
            Box::new(|cc| Ok(Box::new(ScraplandEditor::new(cc, rx_con, rx_rcon)))),
        );
    });
}
