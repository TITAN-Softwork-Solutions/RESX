
mod color;
mod commands;
mod config;
mod cfgview;
mod disasm;
mod edr;
mod follow_output;
mod follow_scan;
mod follow_trace;
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

use crate::color::{enable_windows_ansi, is_terminal, Colors};
use crate::config::{Cli, Config};

fn main() {
    let started = Instant::now();
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("help") {
        print_usage();
        return;
    }
    if raw_args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return;
    }
    let cli = Cli::parse_from(preprocess_args(&raw_args));

    if cli.example {
        let topic = example_topic(&raw_args, &cli);
        print_examples(topic);
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
                eprintln!("{}", Colors::new(color).err_msg(&format!("Cannot open output file: {}", e)));
                std::process::exit(1);
            }
        }
    } else {
        &mut stdout_lock
    };

    let dll_arg  = cfg.dll.clone();
    let func_arg = cfg.function.clone();
    let is_peinfo_shorthand = dll_arg.eq_ignore_ascii_case("peinfo") && !func_arg.is_empty();

    let is_locate = cfg.locate || cfg.locate_all || cfg.locate_deep || cfg.locate_all_deep || (
        !dll_arg.is_empty()
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
        && cfg.yara.is_empty()
    );

    let result = if is_locate {
        let name = if !func_arg.is_empty() { &func_arg } else { &dll_arg };
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
    } else if !func_arg.is_empty() || !cfg.at_rva.is_empty() || cfg.ordinal > 0 || cfg.show_eat || cfg.show_iat || cfg.sections || cfg.pechk || cfg.hookchk || cfg.intelli || !cfg.cfg_view.is_empty() || !cfg.yara.is_empty() {
        commands::dump::run(&dll_arg, &func_arg, &cfg, w, &c)
    } else if dll_arg.is_empty() {
        eprintln!("{}", c.err_msg(
            "Specify a command such as dump, peinfo, sections, eat, iat, syms, pechk, callers, locate, or yara"
        ));
        eprintln!("{}", c.dim("Run `resx help` for usage"));
        std::process::exit(1);
    } else {
        eprintln!("{}", c.err_msg(
            "Incomplete command. Use `resx dump <dll> <function>`, `resx sections <dll>`, `resx peinfo <dll>`, or `resx help`"
        ));
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

    if let Some(ref mut f) = file_handle { f.flush().ok(); } else { stdout_lock.flush().ok(); }
}

fn print_usage() {
    eprintln!(r#"
resx v1.0.0
Resolve exports, symbols, PE metadata, and caller relationships in Windows images.

USAGE
  resx dump <dll> <function> [options]
  resx dump <dll> --at <rva> [options]
  resx dump <dll> --ordinal <n> [options]
  resx cfg <dll> <function> [options]

  resx peinfo <dll> [options]
  resx sections <dll> [options]
  resx eat <dll> [options]
  resx iat <dll> [options]
  resx syms <dll> [options]
  resx pechk <dll> [options]

  resx callers <dll> <function> [follow options]

  resx locate <funcname> [options]
  resx locate-all <funcname> [options]
  resx locate-sym <funcname> [options]
  resx locate-all-sym <funcname> [options]

  resx yara <dll> <rule.yar> [options]

  resx help
  resx <command> --example

COMMANDS
  dump        Disassemble or reconstruct one target by name, RVA, or ordinal.
  cfg         Show a control-flow graph view for one target.
  peinfo      Show PE metadata, version resources, signer info, and headers.
  sections    Show section layout, entropy, and protection expectations.
  eat         Dump the Export Address Table.
  iat         Dump the Import Address Table.
  syms        Dump resolved module and PDB symbols.
  pechk       Run PE header and layout anomaly checks.
  callers     Reverse-trace callers of a target function across images.
  locate      Find the first export-backed match for a function name.
  locate-all  Show every export-backed match for a function name.
  locate-sym  Find the first export/symbol-backed match.
  locate-all-sym
              Show every export/symbol-backed match.
  yara        Scan a PE image with one or more YARA rules.
  help        Show this help text.

DUMP OPTIONS
  --at <rva>                 dump by RVA instead of by function name
  --ordinal <n>              dump by export ordinal
  --recomp                   show C-like reconstruction
  --c-out <file>             write reconstruction to a C file
  --edrchk                   compare disk vs loaded-memory prologue
  --hookchk                  show static entry-hook / thunk indicators
  --xrefs                    show call targets (deduplicated flat list)
  --strings                  show referenced string literals
  --funcs                    show API call map: every CALL/JMP with its resolved target
  --funcs-depth <N>          recursively trace internal subs N levels deep (implies --funcs)
  --cfg text                 show a colour-coded basic control-flow graph
  --follow-jmp               follow entry-point thunk
  --rebase <addr>            compute rebased addresses

SYMBOL OPTIONS
  --pdb <file>               explicit PDB file
  --sym-path <path>          extra symbol path(s)
  --sym-server <url>         symbol server override
  --no-pdb                   disable symbol/PDB loading

FOLLOW OPTIONS
  --depth <n>                trace depth
  --max-callers <n>          cap callers per node
  --max-total <n>            cap total graph size
  --format tree|flat|list    output style
  --show-rva                 show owning function RVA
  --show-site                show call-site RVA(s)
  --filter-dll <text>        restrict caller DLL names
  --scan-dir <dir>           add directory to scan
  --scan-dll <dll>           explicitly include an image
  --scan-exe                 include EXEs
  --no-wow64                 skip SysWOW64
  --include <glob>           include filter
  --exclude <glob>           exclude filter
  --max-dll-size <mb>        max image size
  --workers <n>              parallel workers

GLOBAL OPTIONS
  --arch <auto|x86|x64>
  --path <dir>
  --no-system
  --no-cwd
  --no-path
  --bytes / --no-bytes
  --show-offsets
  --intel / --att
  --json
  --out <file>
  --color / --no-color
  --verbose / --quiet

EXAMPLES
  resx dump kernel32.dll CreateFileW --recomp --bytes
  resx dump ntdll.dll NtOpenProcess --edrchk --json
  resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
  resx dump kernel32.dll CreateFileW --funcs
  resx cfg ntdll.dll NtOpenProcess
  resx syms .\J58.dll --pdb .\J58.pdb
  resx sections ntdll.dll
  resx pechk ntdll.dll
  resx yara ntdll.dll .\rules\hooks.yar
  resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
  resx locate-all-sym NtOpenProcess
  resx dump --example
  resx cfg --example
"#);
}

fn example_topic<'a>(raw_args: &'a [String], cli: &'a Cli) -> &'a str {
    const KNOWN: &[&str] = &[
        "dump", "cfg", "peinfo", "sections", "eat", "iat", "syms", "pechk", "callers",
        "locate", "locate-all", "locate-sym", "locate-all-sym", "yara", "edrchk",
        "follow", "recomp", "symbols", "funcs",
    ];
    if raw_args.len() >= 2 {
        let first = raw_args[1].as_str();
        if KNOWN.iter().any(|cmd| first.eq_ignore_ascii_case(cmd)) {
            return first;
        }
    }
    cli.dll.as_deref().unwrap_or("general")
}

fn preprocess_args(raw_args: &[String]) -> Vec<String> {
    if raw_args.is_empty() {
        return Vec::new();
    }
    if raw_args.len() == 1 {
        return raw_args.to_vec();
    }

    let cmd = raw_args[1].to_ascii_lowercase();
    if raw_args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return raw_args.to_vec();
    }
    if raw_args.iter().any(|arg| arg == "--version" || arg == "-V") {
        return raw_args.to_vec();
    }
    if raw_args.iter().any(|arg| arg == "--example") {
        return raw_args.to_vec();
    }

    let mut rewritten = vec![raw_args[0].clone()];
    match cmd.as_str() {
        "dump" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "cfg" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--cfg".to_string());
            rewritten.push("text".to_string());
        }
        "peinfo" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--peinfo".to_string());
        }
        "sections" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--sections".to_string());
        }
        "eat" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--show-eat".to_string());
        }
        "iat" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--show-iat".to_string());
        }
        "syms" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--show-syms".to_string());
        }
        "pechk" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--pechk".to_string());
        }
        "callers" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--follow-callers".to_string());
        }
        "locate" => {
            rewritten.push("--locate".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "locate-all" => {
            rewritten.push("--locate-all".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "locate-sym" => {
            rewritten.push("--locate-sym".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "locate-all-sym" => {
            rewritten.push("--locate-all-sym".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "yara" => {
            if raw_args.len() >= 4 {
                rewritten.push(raw_args[2].clone());
                rewritten.push("--yara".to_string());
                rewritten.push(raw_args[3].clone());
                rewritten.extend(raw_args.iter().skip(4).cloned());
            } else {
                rewritten.extend(raw_args.iter().skip(2).cloned());
            }
        }
        _ => {
            return raw_args.to_vec();
        }
    }
    rewritten
}

fn print_examples(topic: &str) {
    let topic = topic.to_ascii_lowercase();
    let body = match topic.as_str() {
        "edrchk" | "hook" | "hooks" => r#"
EDRCHK EXAMPLES
  resx dump ntdll.dll NtOpenProcess --edrchk
  resx dump kernel32.dll CreateFileW --follow-jmp --edrchk
  resx dump ntdll.dll NtOpenProcess --edrchk --json
  resx dump ntdll.dll NtAllocateVirtualMemory --edrchk --recomp

NOTES
  --edrchk compares the on-disk prologue against the loaded in-memory image.
  It is useful for detecting hotpatches, trampolines, and modified syscall stubs.
"#,
        "locate" | "locate-all" | "locate-sym" | "locate-all-sym" => r#"
LOCATE EXAMPLES
  resx locate OpenProcess
  resx locate NtOpenProcess
  resx locate-all VirtualAlloc
  resx locate-sym RtlpHeapHandleError
  resx locate-all-sym NtOpenProcess
"#,
        "follow" | "callers" => r#"
CALLERS EXAMPLES
  resx callers kernel32.dll CreateFileW
  resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
  resx callers user32.dll MessageBoxW --scan-exe --show-site --json
"#,
        "dump" | "recomp" | "c" => r#"
DUMP EXAMPLES
  resx dump ntdll.dll NtOpenProcess
  resx dump ntdll.dll --at 0x161F40
  resx dump ntdll.dll --ordinal 451
  resx dump kernel32.dll CreateFileW --recomp --c-out CreateFileW.c
  resx dump ntdll.dll NtOpenProcess --recomp --edrchk --c-out NtOpenProcess.c
  resx dump kernel32.dll CreateFileW --funcs               # flat call map
  resx dump kernel32.dll CreateFileW --funcs-depth 3       # recurse 3 levels deep
  resx dump ntdll.dll NtCreateFile --funcs --json          # call map as JSON
  resx dump kernel32.dll CreateFileW --funcs --xrefs       # call map + xref list
"#,
        "cfg" => r#"
CFG EXAMPLES
  resx cfg ntdll.dll NtOpenProcess
  resx cfg blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub
  resx cfg ntdll.dll --at 0x161F40

BLOCK COLOURS
  green    entry block
  red      exit / return block
  yellow   branch block (conditional jump)
  yellow   unconditional jump block
  cyan     normal fall-through block

EDGE COLOURS
  green    [taken]       conditional branch target
  blue     [fallthrough] falls through to next block
  yellow   [jump]        unconditional jump target
  red      [exit]        function return
"#,
        "sections" | "pe" | "pechk" => r#"
PE ANALYSIS EXAMPLES
  resx sections ntdll.dll
  resx pechk ntdll.dll
  resx sections suspicious.dll --json
"#,
        "peinfo" | "info" => r#"
PEINFO EXAMPLES
  resx peinfo ntdll.dll
  resx peinfo .\sample.dll --json
"#,
        "yara" => r#"
YARA EXAMPLES
  resx yara ntdll.dll .\rules\hooks.yar
  resx yara suspicious.dll .\rules\packed.yar --pechk
  resx yara sample.dll .\rules\a.yar --json
"#,
        "symbols" | "pdb" | "syms" => r#"
SYMBOL EXAMPLES
  resx dump ntdll.dll RtlpHeapHandleError
  resx dump ntdll.dll RtlpHeapHandleError --verbose
  resx dump ntdll.dll RtlpHeapHandleError --sym-path "C:\Symbols"
  resx dump ntdll.dll RtlpHeapHandleError --sym-server https://msdl.microsoft.com/download/symbols
  resx syms .\J58.dll --pdb .\J58.pdb
"#,
        "funcs" => r#"
FUNCS EXAMPLES
  resx dump kernel32.dll CreateFileW --funcs
  resx dump kernel32.dll CreateFileW --funcs-depth 2
  resx dump ntdll.dll NtCreateFile --funcs-depth 3
  resx dump ntdll.dll NtOpenProcess --funcs --json
  resx dump kernel32.dll CreateFileW --funcs --xrefs

NOTES
  --funcs shows every CALL and unconditional JMP in the disassembled function,
  each annotated with its resolved target.

  --funcs-depth <N> enables the same call map and additionally recurses into
  internal sub_XXXXXXXX targets, expanding their own call sites as a tree up
  to N levels deep.  Already-visited subs are not re-expanded (cycle-safe).

  Targets are classified as:
    [import]            resolved through the IAT to a specific DLL!Function
    [import · tail call] IAT import reached via a tail-call JMP
    [internal]          direct call to a symbol or sub_XXXXXXXX within this image
    [tail call]         unconditional JMP to an internal target
    [indirect]          indirect call (e.g. call rax) — target not statically known

  --json adds an "api_calls" array to the output for scripting.
"#,
        "eat" => r#"
EAT EXAMPLES
  resx eat kernel32.dll
  resx eat ntdll.dll --json
"#,
        "iat" => r#"
IAT EXAMPLES
  resx iat kernel32.dll
  resx iat user32.dll --json
"#,
        _ => r#"
GENERAL EXAMPLES
  resx dump ntdll.dll NtCreateFile
  resx dump kernel32.dll CreateFileW --recomp
  resx dump ntdll.dll NtOpenProcess --edrchk
  resx dump kernel32.dll CreateFileW --funcs
  resx cfg ntdll.dll NtOpenProcess
  resx locate-all-sym NtOpenProcess

TOPICS
  resx edrchk --example
  resx dump --example
  resx cfg --example
  resx callers --example
  resx locate --example
  resx syms --example
  resx sections --example
  resx peinfo --example
  resx yara --example
  resx eat --example
  resx iat --example
"#,
    };
    println!("{}", body.trim());
}
