mod cfgview;
mod color;
mod commands;
mod config;
mod disasm;
mod edr;
mod follow_output;
mod follow_scan;
mod follow_trace;
mod help;
mod intelli;
mod metadata;
mod output;
mod pdb;
mod pe;
mod recomp;
mod search;
mod symbols;
mod thunk;
mod yara;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use clap::Parser;
use rayon::ThreadPoolBuilder;

use crate::color::{enable_windows_ansi, is_terminal, Colors};
use crate::config::{Cli, Config};
use crate::help::{example_topic, preprocess_args, print_examples, print_usage, version_string};

fn main() {
    let started = Instant::now();
    let raw_args: Vec<String> = std::env::args().collect();

    if is_help_request(&raw_args) {
        print_usage();
        return;
    }
    if is_version_request(&raw_args) {
        println!("{}", version_string());
        return;
    }

    let cli = Cli::parse_from(preprocess_args(&raw_args));
    if cli.example {
        print_examples(example_topic(&raw_args, &cli));
        return;
    }

    let color = if cli.no_color {
        false
    } else if cli.force_color {
        true
    } else {
        enable_windows_ansi() && is_terminal()
    };

    let cfg = Config::from_cli(&cli, color);
    let c = Colors::new(color && !cfg.json);

    if cfg.workers > 0 {
        let _ = ThreadPoolBuilder::new()
            .num_threads(cfg.workers)
            .build_global();
    }

    let stdout = io::stdout();
    let mut stdout_lock = BufWriter::new(stdout.lock());
    let mut file_handle: Option<BufWriter<File>> = None;

    let w: &mut dyn Write = if !cfg.out_file.is_empty() {
        match File::create(&cfg.out_file) {
            Ok(f) => {
                file_handle = Some(BufWriter::new(f));
                file_handle.as_mut().unwrap()
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    Colors::new(color).err_msg(&format!("Cannot open output file: {}", e))
                );
                std::process::exit(1);
            }
        }
    } else {
        &mut stdout_lock
    };

    let dll_arg = cfg.dll.clone();
    let func_arg = cfg.function.clone();
    let is_peinfo_shorthand = dll_arg.eq_ignore_ascii_case("peinfo") && !func_arg.is_empty();

    let is_locate = cfg.locate
        || cfg.locate_all
        || cfg.locate_deep
        || cfg.locate_all_deep
        || (!dll_arg.is_empty()
            && !dll_arg.eq_ignore_ascii_case("peinfo")
            && func_arg.is_empty()
            && cfg.at_rva.is_empty()
            && cfg.ordinal == 0
            && !cfg.show_eat
            && !cfg.show_iat
            && !cfg.show_syms
            && !cfg.follow_callers
            && !cfg.peinfo
            && !cfg.sections
            && !cfg.pechk
            && !cfg.hookchk
            && !cfg.intelli
            && cfg.cfg_view.is_empty()
            && cfg.yara.is_empty());

    let result = if cli.update {
        commands::update::run(&cfg, w, &c)
    } else if is_locate {
        let name = if !func_arg.is_empty() {
            &func_arg
        } else {
            &dll_arg
        };
        if name.is_empty() {
            eprintln!("{}", c.err_msg("Specify a function name to locate"));
            print_usage();
            std::process::exit(1);
        }
        commands::locate::run(name, &cfg, w, &c)
    } else if is_peinfo_shorthand {
        commands::peinfo::run(&func_arg, &cfg, w, &c)
    } else if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("cfg") {
        commands::cfg::run(&dll_arg, &func_arg, &cfg, w, &c)
    } else if cfg.peinfo && !dll_arg.is_empty() && func_arg.is_empty() {
        commands::peinfo::run(&dll_arg, &cfg, w, &c)
    } else if cfg.follow_callers && !dll_arg.is_empty() && !func_arg.is_empty() {
        commands::follow::run(&dll_arg, &func_arg, &cfg, w, &c)
    } else if cfg.show_eat && func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        commands::show_eat::run(&dll_arg, &cfg, w, &c)
    } else if cfg.show_iat && func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        commands::show_iat::run(&dll_arg, &cfg, w, &c)
    } else if cfg.show_syms && func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        commands::show_syms::run(&dll_arg, &cfg, w, &c)
    } else if !func_arg.is_empty()
        || !cfg.at_rva.is_empty()
        || cfg.ordinal > 0
        || cfg.show_eat
        || cfg.show_iat
        || cfg.sections
        || cfg.pechk
        || cfg.hookchk
        || cfg.intelli
        || !cfg.cfg_view.is_empty()
        || !cfg.yara.is_empty()
    {
        commands::dump::run(&dll_arg, &func_arg, &cfg, w, &c)
    } else if dll_arg.is_empty() {
        eprintln!(
            "{}",
            c.err_msg(
                "Specify a command such as dump, cfg, peinfo, sections, eat, iat, syms, pechk, callers, locate, yara, update, or help",
            )
        );
        eprintln!("{}", c.dim("Run `resx help` for usage"));
        std::process::exit(1);
    } else {
        eprintln!(
            "{}",
            c.err_msg(
                "Incomplete command. Use `resx dump <dll> <function>`, `resx cfg <dll> <function>`, `resx peinfo <dll>`, `resx update`, or `resx help`",
            )
        );
        eprintln!("{}", c.dim("Run `resx help` for usage"));
        std::process::exit(1);
    };

    if let Err(e) = result {
        eprintln!("{}", c.err_msg(&e));
        std::process::exit(1);
    }

    if !cfg.json {
        let elapsed = started.elapsed();
        let secs = elapsed.as_secs_f64();
        let pretty = if secs >= 60.0 {
            format!("{:.2}m", secs / 60.0)
        } else if secs >= 1.0 {
            format!("{:.2}s", secs)
        } else {
            format!("{}ms", elapsed.as_millis())
        };
        writeln!(w, "\n{}", c.dim(&format!("<completed in {}>", pretty))).ok();
    }

    if let Some(ref mut f) = file_handle {
        f.flush().ok();
    } else {
        stdout_lock.flush().ok();
    }
}

fn is_help_request(raw_args: &[String]) -> bool {
    raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("help")
        || raw_args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn is_version_request(raw_args: &[String]) -> bool {
    raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("version")
        || raw_args.iter().any(|arg| arg == "--version" || arg == "-V")
}
