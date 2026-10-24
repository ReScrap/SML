#![feature(exit_status_error)]
use std::{
    collections::HashMap, path::{Path, PathBuf}, process::{Command as ProcCommand, Stdio}, time::Instant,
};

use cargo_metadata::{Message, Package, PackageId};
use clap::{Args, Parser};
use color_eyre::{eyre::bail, install, Result};
use serde::Deserialize;
use tracing::*;
use human_repr::*;

const APP_ID: u32 = 897610;
const BUILD_ID: u64 = 7863744;

#[derive(Debug, Args)]
struct BuildArgs {
    /// Build in release mode
    #[arg(short, long)]
    release: bool,
    /// Install the modloader and default plugins
    #[arg(short, long)]
    install: bool,
    /// Run game after installing modloader
    #[arg(long)]
    run: bool,
    /// Arguments passed to Scrapland
    args: Vec<String>,
}

#[derive(Debug, Parser)]
enum Task {
    /// Build modloader and standard plugins
    Build(BuildArgs),
}

#[derive(Debug, Deserialize)]
struct ModMeta {
    #[serde(default)]
    mod_loader: bool,
    #[serde(default)]
    target_file: String,
}

fn replace_base_name(path: &Path, new_name: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .expect("path has no file name")
        .to_str()
        .expect("file name is not valid UTF-8");

    let new_file_name = match file_name.find('.') {
        Some(idx) => format!("{}{}", new_name, &file_name[idx..]),
        None => new_name.to_owned(),
    };

    path.with_file_name(new_file_name)
}

fn main() -> Result<()> {
    install()?;
    tracing_subscriber::fmt().init();
    let task = Task::parse();
    match &task {
        Task::Build(args) => build_sml(args),
    }
}

fn build_sml(args: &BuildArgs) -> Result<()> {
    let meta = cargo_metadata::MetadataCommand::new().no_deps().exec()?;

    let pkg_ids: HashMap<PackageId, Package> = meta
        .workspace_default_packages()
        .iter()
        .map(|&p| (p.clone().id, p.clone()))
        .collect();

    info!("Building modloader and standard plugins");

    let mut cargo_args = vec!["build", "--message-format=json-render-diagnostics"];
    if args.release {
        cargo_args.push("--release");
    }
    let t_start = Instant::now();
    let mut command = ProcCommand::new("cargo")
        .args(cargo_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let mut mods = HashMap::new();
    let mut loader = None;

    let reader = std::io::BufReader::new(command.stdout.take().unwrap());
    for message in Message::parse_stream(reader) {
        match message? {
            Message::CompilerArtifact(artifact)
                if let Some(pkg) = pkg_ids.get(&artifact.package_id).cloned()
                    && artifact.target.is_cdylib() =>
            {
                let Some(meta) = serde_json::from_value::<Option<ModMeta>>(pkg.metadata.clone())?
                else {
                    warn!("{} doesn't have ReScrap metadata", artifact.package_id);
                    continue;
                };
                if meta.mod_loader {
                    loader = Some((meta.target_file, artifact));
                } else {
                    mods.insert(artifact.target.name.clone(), artifact);
                }
            }
            Message::CompilerArtifact(_) | Message::BuildScriptExecuted(_) => {}
            Message::CompilerMessage(msg) => {
                info!("{}", msg.message.to_string().trim_end());
            }
            _ => {}
        }
    }

    command.wait()?.exit_ok()?;

    let Some((target_basename, artifact)) = loader else {
        bail!("Failed to build modloader!");
    };

    info!("Built modloader and {} plugin(s) in {}", mods.len(), t_start.elapsed().human_duration());

    if args.run || args.install {
        let Some((app, lib)) = steamlocate::locate()?.find_app(APP_ID)? else {
            bail!("Failed to find Scrapland");
        };
        let app_name = app.name.as_deref().unwrap_or("<Unknown>");
        info!(
            "Found {} (App ID: {}) Build {} at {}",
            app.name.as_deref().unwrap_or("<Unknown>"),
            app.app_id,
            app.build_id.unwrap_or(0),
            lib.resolve_app_dir(&app).display()
        );

        if app.build_id.unwrap_or(0) != BUILD_ID {
            warn!("Unexpected build ID, should be {BUILD_ID}");
        }

        let scrap_dir = lib.resolve_app_dir(&app);
        let loader_dir = scrap_dir.join("Bin");
        let plugin_dir = scrap_dir.join("plugins");
        fs_err::create_dir_all(&plugin_dir)?;

        if args.install {
            fs_err::copy("init.lua", scrap_dir.join("init.lua"))?;
            for path in artifact.filenames {
                if path
                    .file_name()
                    .map(|f| f.chars().filter(|c| *c == '.').count())
                    .unwrap_or(0)
                    != 1
                {
                    continue;
                };
                let path = path.into_std_path_buf();
                let filename = replace_base_name(&path, &target_basename);
                let dest = loader_dir.join(
                    filename
                        .file_name()
                        .expect("Artifacts should have a filename!"),
                );
                info!("Copying {} to {}", path.display(), dest.display());
                fs_err::copy(path, dest)?;
            }

            for (id, artifact) in mods.iter() {
                for path in artifact.filenames.iter().cloned() {
                    if path
                        .file_name()
                        .map(|f| f.chars().filter(|c| *c == '.').count())
                        .unwrap_or(0)
                        != 1
                    {
                        continue;
                    };
                    let path = path.into_std_path_buf();
                    let filename = replace_base_name(&path, id);
                    let dest = plugin_dir.join(
                        filename
                            .file_name()
                            .expect("Artifacts should have a filename!"),
                    );
                    info!("Copying {} to {}", path.display(), dest.display());
                    fs_err::copy(path, dest)?;
                }
            }
        }

        if args.run {
            let args = &args.args;
            if !args.is_empty() {
                info!("Launching {app_name} with arguments: {args:?}");
            } else {
                info!("Launching {app_name}");
            }
            let args = args.join(" ");
            open::that(format!("steam://run/{APP_ID}//{args}"))?;
        }
    }

    Ok(())
}
