use std::io::Write;

use crate::color::Colors;
use crate::config::Config;
use crate::follow_output::{count_nodes, node_to_json, print_call_flat, print_call_list, print_call_tree};
use crate::follow_scan::{build_scan_list, find_target_dll, FollowScanConfig};
use crate::follow_trace::{build_call_tree, FuncRef, TraceCtx};
use crate::pdb::load_pdb_symbol;
use crate::pe::{parse_pe, read_exports};

pub fn run(dll_arg: &str, func_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let scan_cfg = FollowScanConfig::from_config(cfg);

    if !cfg.quiet {
        writeln!(w, "{}", c.info(&format!("Locating '{}'...", dll_arg))).ok();
    }
    let dll_path = find_target_dll(dll_arg, &scan_cfg)?;
    if !cfg.quiet {
        writeln!(w, "{}", c.ok(&format!("Found: {}", dll_path.display()))).ok();
    }

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let exports = read_exports(&pe, &raw);

    if !cfg.quiet {
        writeln!(w, "{}", c.info(&format!("Architecture: x{}  |  ImageBase: 0x{:X}", pe.arch, pe.image_base))).ok();
    }

    let dll_name = dll_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let (target_name, target_rva, is_internal) =
        resolve_target(&exports, &dll_path_str, &dll_name, func_arg, pe.image_base, cfg, w, c)?;
    let target = FuncRef {
        dll: dll_name.clone(),
        dll_path: dll_path_str.clone(),
        name: target_name.clone(),
        rva: target_rva,
        va: pe.image_base + target_rva as u64,
        is_internal,
    };

    if !cfg.quiet {
        writeln!(w, "{}", c.ok(&format!("Target: {}!{}  RVA:0x{:08X}  VA:0x{:016X}", target.dll, target.name, target.rva, target.va))).ok();
    }

    let scan_paths = build_scan_list(&scan_cfg, &dll_path);
    if !cfg.quiet {
        writeln!(w, "{}", c.info(&format!("Scan list: {} file(s)  |  depth: {}  |  workers: {}", scan_paths.len(), scan_cfg.depth, scan_cfg.workers))).ok();
    }

    let mut visited = std::collections::HashMap::new();
    visited.insert(target.key(), true);
    let ctx = TraceCtx {
        cfg: &scan_cfg,
        scan_paths: &scan_paths,
        target_arch: pe.arch,
        visited: std::sync::Mutex::new(visited),
        total: std::sync::Mutex::new(0usize),
    };

    let root = build_call_tree(target.clone(), 0, &ctx, w, c);
    let (total_refs, unique_fns) = count_nodes(&root);

    if !cfg.quiet && !cfg.json {
        writeln!(w).ok();
    }

    if cfg.json {
        writeln!(w, "{}", serde_json::to_string_pretty(&node_to_json(&root)).unwrap_or_default()).ok();
    } else {
        match cfg.follow_format.as_str() {
            "flat" => print_call_flat(w, &root, &scan_cfg, c),
            "list" => {
                writeln!(w, "{}  (unique callers)", c.bold(&c.b_yellow(&target.name))).ok();
                print_call_list(w, &root, &scan_cfg, c);
            }
            _ => print_call_tree(w, &root, "", true, &scan_cfg, c),
        }

        if !cfg.quiet {
            writeln!(w).ok();
            writeln!(w, "{}", c.dim(&format!("  {} total caller references  |  {} unique functions", total_refs, unique_fns))).ok();
        }
    }

    Ok(())
}

fn find_export<'a>(exports: &'a [crate::pe::Export], name: &str) -> Option<&'a crate::pe::Export> {
    if let Some(e) = exports.iter().find(|e| e.name == name) {
        return Some(e);
    }
    if let Some(stripped) = name.strip_prefix('#') {
        if let Ok(n) = stripped.parse::<u32>() {
            return exports.iter().find(|e| e.ordinal == n);
        }
    }
    None
}

fn resolve_target(
    exports: &[crate::pe::Export],
    dll_path: &str,
    dll_name: &str,
    func_arg: &str,
    image_base: u64,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(String, u32, bool), String> {
    if let Some(export) = find_export(exports, func_arg) {
        return Ok((export.name.clone(), export.rva, false));
    }

    if !cfg.no_pdb {
        if !cfg.quiet {
            writeln!(w, "{}", c.info("Not found in EAT, trying PDB symbols...")).ok();
        }
        if let Some(rva) = load_pdb_symbol(
            dll_path,
            func_arg,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            image_base,
            cfg.verbose,
        ) {
            if !cfg.quiet {
                writeln!(w, "{}", c.ok(&format!(
                    "{} @ RVA 0x{:08X}  (from PDB)",
                    func_arg, rva
                ))).ok();
            }
            return Ok((func_arg.to_string(), rva, true));
        }
    }

    let lf = func_arg.to_ascii_lowercase();
    let suggestions: Vec<&str> = exports
        .iter()
        .filter(|e| e.name.to_ascii_lowercase().contains(&lf))
        .take(8)
        .map(|e| e.name.as_str())
        .collect();

    if !suggestions.is_empty() {
        writeln!(w, "{}", c.warn("Similar exports:")).ok();
        for suggestion in suggestions {
            writeln!(w, "  {}", c.cyan(suggestion)).ok();
        }
    }

    Err(format!(
        "'{}' not found in exports or PDB symbols for {}",
        func_arg, dll_name
    ))
}
