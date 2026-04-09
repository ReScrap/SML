use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Expr, FnArg, Ident, ItemFn, LitBool, LitStr, Pat, ReturnType, Token, Type,
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
};

struct HookArgs {
    rva: Expr,
    abi: LitStr,
    enable: bool,
}

impl Parse for HookArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let rva: Expr = input.parse()?;
        input.parse::<Token![,]>()?;

        let abi = if input.peek(LitStr) {
            input.parse()?
        } else {
            let ident: Ident = input.parse()?;
            LitStr::new(&ident.to_string(), ident.span())
        };

        // Optional third argument: a boolean literal (defaults to true)
        let enable = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let lb: LitBool = input.parse()?;
            lb.value
        } else {
            true
        };

        if !input.is_empty() {
            return Err(input.error("expected #[hook(<rva>, <abi>)]"));
        }

        Ok(Self { rva, abi, enable })
    }
}

fn to_pascal_case(s: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for ch in s.chars() {
        if ch == '_' {
            capitalize = true;
            continue;
        }
        if capitalize {
            out.extend(ch.to_uppercase());
            capitalize = false;
        } else {
            out.push(ch);
        }
    }
    out
}

#[proc_macro_attribute]
pub fn hook(attr: TokenStream, item: TokenStream) -> TokenStream {
    let HookArgs { rva, abi, enable } = parse_macro_input!(attr as HookArgs);
    let mut f = parse_macro_input!(item as ItemFn);

    if f.sig.generics.params.iter().next().is_some() {
        return syn::Error::new_spanned(&f.sig.generics, "#[hook] does not support generics")
            .to_compile_error()
            .into();
    }

    let fn_name = f.sig.ident.clone();
    let vis = f.vis.clone();

    f.sig.safety = syn::Safety::Unsafe(Default::default());
    f.sig.abi = Some(parse_quote!(extern #abi));

    let mut arg_types = Vec::<Type>::new();
    for arg in &f.sig.inputs {
        match arg {
            FnArg::Typed(pat_ty) => {
                if !matches!(&*pat_ty.pat, Pat::Ident(_)) {
                    return syn::Error::new_spanned(
                        &pat_ty.pat,
                        "#[hook] requires identifier argument patterns",
                    )
                    .to_compile_error()
                    .into();
                }
                arg_types.push((*pat_ty.ty).clone());
            }
            FnArg::Receiver(receiver) => {
                return syn::Error::new_spanned(receiver, "#[hook] cannot be used on methods")
                    .to_compile_error()
                    .into();
            }
        }
    }

    let ret_ty: Type = match &f.sig.output {
        ReturnType::Default => parse_quote!(()),
        ReturnType::Type(_, ty) => *ty.clone(),
    };
    let func_ty: Type = parse_quote!(unsafe extern #abi fn(#(#arg_types),*) -> #ret_ty);

    let hook_struct = format_ident!("{}Hook", to_pascal_case(&fn_name.to_string()));
    let installer_fn = format_ident!("__install_{}", fn_name);
    let installer_static = format_ident!("__{}_HOOK_INSTALLER", fn_name);
    let disable_fn = format_ident!("{}_disable_hook", fn_name);
    let enable_fn = format_ident!("{}_enable_hook", fn_name);

    f.block.stmts.insert(
        0,
        parse_quote! {
            let original: #func_ty = <#hook_struct as crate::Hookable>::get();
        },
    );

    let expanded = quote! {
        #f

        #vis struct #hook_struct;

        impl crate::Hookable for #hook_struct {
            const RVA: usize = #rva;
            type Func = #func_ty;
            const HOOK: *const () = #fn_name as *const ();
            const NAME: &'static str = stringify!(#fn_name);
        }

        fn #installer_fn() -> ::anyhow::Result<()> {
            <#hook_struct as crate::Hookable>::hook()?;
            if !#enable {
                <#hook_struct as crate::Hookable>::disable()?;
            } else {
                <#hook_struct as crate::Hookable>::enable()?;
            }
            Ok(())
        }

        #vis fn #disable_fn() -> ::anyhow::Result<()> {
            <#hook_struct as crate::Hookable>::disable()
        }

        #vis fn #enable_fn() -> ::anyhow::Result<()> {
            <#hook_struct as crate::Hookable>::enable()
        }

        #[allow(non_upper_case_globals)]
        #[linkme::distributed_slice(crate::HOOK_INSTALLERS)]
        static #installer_static: crate::HookInstaller = #installer_fn;
    };

    TokenStream::from(expanded)
}
