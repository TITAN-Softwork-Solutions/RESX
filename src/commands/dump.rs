
use std::io::Write;
use serde::Serialize;

use crate::cfgview::{detect_static_hook_indicators, render_cfg_colored, render_cfg_text};
use crate::color::Colors;
use crate::config::Config;
use crate::disasm::{collect_api_calls, disassemble_at, find_string_refs, find_xrefs, ApiCall};
use crate::edr::{check_prologue, EdrCheckResult};
use crate::intelli::{analyze_image, IntelliFinding};
use crate::output::{print_c_recomp, print_eat, print_iat, print_insns, print_pe_anomalies, print_sections, print_sep, print_yara_matches, StageProgress};
use crate::pdb::{load_pdb_symbol, load_pdb_symbols};
use crate::pe::{parse_pe, read_exports, read_imports, Export, PeAnomaly, PeSection};
use crate::recomp::recomp_c;
use crate::search::find_dll_path;
use crate::symbols::SymbolIndex;
use crate::thunk::{follow_jmp_thunk, ThunkResolution};
use crate::yara::scan_file;


#[derive(Serialize)]
struct InsnJson {
    rva:     String,
    va:      String,
    #[serde(skip_serializing_if = "String::is_empty")]
    rebased_va: String,
    bytes:   String,
    text:    String,
    #[serde(skip_serializing_if = "String::is_empty")]
    comment: String,
}

#[derive(Serialize)]
struct FuncResult {
    dll:           String,
    dll_path:      String,
    #[serde(skip_serializing_if = "String::is_empty")]
    function:      String,
    #[serde(skip_serializing_if = "String::is_empty")]
    rva:           String,
    #[serde(skip_serializing_if = "String::is_empty")]
    va:            String,
    #[serde(skip_serializing_if = "String::is_empty")]
    rebased_va:    String,
    image_base:    String,
    arch:          String,
    entry_point:   String,
    size_of_image: String,
    size_of_headers: String,
    section_alignment: String,
    file_alignment: String,
    checksum: String,
    subsystem: String,
    dll_characteristics: String,
    header_corrupt: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pe_anomalies:  Vec<PeAnomalyJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sections:      Vec<PeSectionJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    yara_matches:  Vec<YaraJson>,
    #[serde(skip_serializing_if = "is_zero_usize")]
    size_bytes:    usize,
    #[serde(skip_serializing_if = "is_zero_usize")]
    insn_count:    usize,
    pdb_loaded:    bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    followed_jmp:  String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    instructions:  Vec<InsnJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xrefs:         Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    strings:       Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    intelli_findings: Vec<IntelliFinding>,
    #[serde(skip_serializing_if = "String::is_empty")]
    recomp:        String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cfg:           String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hook_indicators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edrchk:        Option<EdrJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    api_calls:     Vec<ApiCallJson>,
}

#[derive(Serialize)]
struct EdrJson {
    in_memory_available: bool,
    loaded_for_check: bool,
    compared_len: usize,
    modified: bool,
    diff_offsets: Vec<usize>,
    disk_bytes: String,
    memory_bytes: String,
}

#[derive(Serialize)]
struct PeSectionJson {
    name: String,
    rva: String,
    virtual_size: String,
    raw_offset: String,
    raw_size: String,
    protections: String,
    expected: String,
    entropy: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    note: String,
}

#[derive(Serialize)]
struct PeAnomalyJson {
    severity: String,
    kind: String,
    detail: String,
}

#[derive(Serialize)]
struct ApiCallJson {
    rva:         String,
    kind:        String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_rva:  String,
    label:       String,
    #[serde(skip_serializing_if = "String::is_empty")]
    dll:         String,
    is_import:   bool,
    is_indirect: bool,
}

#[derive(Serialize)]
struct YaraJson {
    rule: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    namespace: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    file: String,
}


pub fn run(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if !cfg.cfg_view.is_empty() && !cfg.cfg_view.eq_ignore_ascii_case("text") {
        return Err(format!("unsupported --cfg format '{}'; use 'text'", cfg.cfg_view));
    }

    let only_metadata = func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0;
    let want_recomp = cfg.recomp || !cfg.c_out.is_empty();
    let want_cfg = cfg.cfg_view.eq_ignore_ascii_case("text");
    let want_hookchk = cfg.hookchk || cfg.edrchk;
    let want_intelli = cfg.intelli;
    let mut progress = StageProgress::new(count_dump_steps(cfg, only_metadata, want_recomp), !cfg.quiet && !cfg.json);

    if !cfg.quiet {
        writeln!(w, "{}", c.info(&format!("Searching for '{}'...", dll_arg))).ok();
    }
    let dll_path = find_dll_path(dll_arg, cfg)?;
    progress.tick("locating target image");
    let dll_name = dll_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();

    if !cfg.quiet {
        writeln!(w, "{}", c.ok(&format!("Found: {}", dll_path_str))).ok();
    }

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    progress.tick("reading image");

    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    progress.tick("parsing PE headers");
    let pe_arch = pe.arch;
    let arch = cfg.effective_arch(pe_arch);
    let arch_str = format!("x{}", arch);
    let image_base = pe.image_base;
    let rebase = cfg.rebase_addr()?;

    if !cfg.quiet {
        let mut line = format!("Architecture: {}  |  ImageBase: 0x{:X}", arch_str, image_base);
        if let Some(base) = rebase {
            line.push_str(&format!("  |  Rebase: 0x{:X}", base));
        }
        writeln!(w, "{}", c.info(&line)).ok();
    }

    if !cfg.quiet {
        writeln!(w, "{}", c.info("Parsing export table...")).ok();
    }
    let exports = read_exports(&pe, &raw);
    progress.tick("reading export table");
    if !cfg.quiet && !exports.is_empty() {
        writeln!(w, "{}", c.ok(&format!("Found {} exports", exports.len()))).ok();
    }

    let pdb_symbols = if cfg.no_pdb {
        Vec::new()
    } else {
        match load_pdb_symbols(
            &dll_path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            cfg.verbose,
        ) {
            Ok(symbols) => symbols,
            Err(err) => {
                if cfg.verbose && !cfg.quiet {
                    writeln!(w, "{}", c.dim(&format!("PDB symbol enumeration unavailable: {}", err))).ok();
                }
                Vec::new()
            }
        }
    };
    if !cfg.no_pdb {
        progress.tick("loading symbols");
    }
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, image_base);
    let imports = read_imports(&pe, &raw);
    progress.tick("reading import table");
    let yara_matches = if cfg.yara.is_empty() {
        Vec::new()
    } else {
        scan_file(&dll_path_str, &cfg.yara)?
    };
    if !cfg.yara.is_empty() {
        progress.tick("running YARA rules");
    }

    if cfg.show_eat {
        print_eat(w, &exports, &dll_name, c);
    }

    if cfg.show_iat {
        print_iat(w, &imports, &dll_name, c);
    }

    if cfg.sections && !cfg.json {
        print_sections(w, &pe, c);
    }

    if cfg.pechk && !cfg.json {
        print_pe_anomalies(w, &pe.anomalies, c);
    }

    if !cfg.yara.is_empty() && !cfg.json {
        print_yara_matches(w, &yara_matches, c);
    }

    let metadata_intelli = if want_intelli && only_metadata {
        let findings = analyze_image(&raw, &imports, None);
        if !cfg.json {
            print_intelli_findings(w, &findings, c);
        }
        progress.tick("running Intelli triage");
        findings
    } else {
        Vec::new()
    };

    if only_metadata {
        progress.finish();
        if cfg.json {
            let result = FuncResult {
                dll: dll_name,
                dll_path: dll_path_str,
                function: String::new(),
                rva: String::new(),
                va: String::new(),
                rebased_va: String::new(),
                image_base: format!("0x{:016X}", image_base),
                arch: arch_str,
                entry_point: format!("0x{:08X}", pe.entry_point),
                size_of_image: format!("0x{:08X}", pe.size_of_image),
                size_of_headers: format!("0x{:08X}", pe.size_of_headers),
                section_alignment: format!("0x{:08X}", pe.section_alignment),
                file_alignment: format!("0x{:08X}", pe.file_alignment),
                checksum: format!("0x{:08X}", pe.checksum),
                subsystem: format!("0x{:04X}", pe.subsystem),
                dll_characteristics: format!("0x{:04X}", pe.dll_characteristics),
                header_corrupt: pe.header_corruption_detected(),
                pe_anomalies: pe.anomalies.iter().map(to_anomaly_json).collect(),
                sections: pe.sections.iter().map(to_section_json).collect(),
                yara_matches: yara_matches.iter().map(to_yara_json).collect(),
                size_bytes: 0,
                insn_count: 0,
                pdb_loaded: !pdb_symbols.is_empty(),
                followed_jmp: String::new(),
                instructions: Vec::new(),
                xrefs: Vec::new(),
                strings: Vec::new(),
                intelli_findings: metadata_intelli,
                recomp: String::new(),
                cfg: String::new(),
                hook_indicators: Vec::new(),
                edrchk: None,
                api_calls: Vec::new(),
            };
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            writeln!(w, "{}", json).ok();
        }
        return Ok(());
    }

    let (target_rva, resolved_name, pdb_loaded) =
        resolve_function(func_arg, &exports, &pe, &raw, &dll_path_str, image_base, cfg, w, c)?;
    progress.tick("resolving target");

    let mut file_off = pe.rva_to_offset(target_rva)
        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", target_rva))?;
    let mut target_rva = target_rva;

    let mut followed_desc = String::new();

    let entry_thunk = follow_jmp_thunk(&raw, &pe, target_rva);

    if cfg.follow_jmp {
        if let Some(res) = entry_thunk.as_ref() {
            match &res {
                ThunkResolution::Iat { dll, func, .. } if !dll.is_empty() => {
                    if !cfg.quiet {
                        writeln!(w).ok();
                        let title = format!("{}!{}  [RVA 0x{:08X}]  — STUB", dll_name, resolved_name, target_rva);
                        writeln!(w, "{}", c.bold(&c.b_yellow(&title))).ok();
                        print_sep(w, c, 88);
                        if let Ok(stub_insns) = disassemble_at(&raw, file_off, target_rva, arch, image_base, &exports, Some(&symbol_index), cfg) {
                            print_insns(w, &stub_insns, cfg, c);
                        }
                        print_sep(w, c, 88);
                        writeln!(w, "{}", c.warn(&format!(
                            "STUB  {}!{}  →  {}!{}", dll_name, resolved_name, dll, func
                        ))).ok();
                        writeln!(w, "{}", c.info(&format!("Auto-following into {}...", dll))).ok();
                    }
                    let new_cfg = cfg.clone();
                    return run(dll, func, &new_cfg, w, c);
                }
                ThunkResolution::Direct { target_rva: new_rva } => {
                    followed_desc = res.desc();
                    target_rva = *new_rva;
                    file_off = pe.rva_to_offset(target_rva)
                        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", target_rva))?;
                    if !cfg.quiet {
                        writeln!(w, "{}", c.info(&format!("Following: {}", res.desc()))).ok();
                    }
                }
                ThunkResolution::IatUnresolved { .. } => {
                    followed_desc = res.desc();
                    if !cfg.quiet {
                        writeln!(w, "{}", c.warn(&format!("Unresolved thunk: {}", res.desc()))).ok();
                    }
                }
                _ => {}
            }
        }
    }

    if !cfg.no_pdb && !cfg.quiet {
        writeln!(w, "{}", c.info("Symbols: local cache first, then configured paths, then Microsoft symbol server")).ok();
    }

    if !cfg.quiet {
        writeln!(w, "{}", c.info(&format!(
            "Disassembling from RVA 0x{:08X} (file offset 0x{:X})...",
            target_rva, file_off
        ))).ok();
    }

    let insns = disassemble_at(&raw, file_off, target_rva, arch, image_base, &exports, Some(&symbol_index), cfg)
        .map_err(|e| format!("disassembly: {}", e))?;
    progress.tick("disassembling function");

    let edr_result = if cfg.edrchk {
        let max_len = insns.iter().take(8).map(|i| i.bytes.len()).sum::<usize>().clamp(16, 64);
        Some(check_prologue(&dll_path_str, target_rva, &raw[file_off..], max_len)?)
    } else {
        None
    };
    if cfg.edrchk {
        progress.tick("checking in-memory prologue");
    }

    let func_size_bytes = if insns.is_empty() { 0 } else {
        let last = insns.last().unwrap();
        (last.rva - insns[0].rva) as usize + last.bytes.len()
    };

    if !cfg.json {
        writeln!(w).ok();
        let mut title = format!("{}!{}  [RVA 0x{:08X}", dll_name, resolved_name, target_rva);
        if let Some(base) = rebase {
            title.push_str(&format!(", REBASE 0x{:X}", base + target_rva as u64));
        } else {
            title.push_str(&format!(", VA 0x{:X}", image_base + target_rva as u64));
        }
        title.push(']');
        writeln!(w, "{}", c.bold(&c.b_yellow(&title))).ok();
        if let Some(base) = rebase {
            writeln!(w, "{}", c.dim(&format!(
                "  Base0/RVA: 0x{:08X}  |  PE-VA: 0x{:X}  |  Rebased-VA: 0x{:X}",
                target_rva,
                image_base + target_rva as u64,
                base + target_rva as u64
            ))).ok();
        } else {
            writeln!(w, "{}", c.dim(&format!(
                "  Base0/RVA: 0x{:08X}  |  VA: 0x{:X}",
                target_rva,
                image_base + target_rva as u64
            ))).ok();
        }
        print_sep(w, c, 88);
        print_insns(w, &insns, cfg, c);
        print_sep(w, c, 88);
        writeln!(w, "{}", c.ok(&format!(
            "Done: {} instructions, ~{} bytes", insns.len(), func_size_bytes
        ))).ok();
    }

    if let Some(edr) = &edr_result {
        print_edr_report(w, edr, c);
    }

    let mut hook_indicators = if want_hookchk {
        detect_static_hook_indicators(&insns, entry_thunk.as_ref())
    } else {
        Vec::new()
    };
    if let Some(edr) = &edr_result {
        if edr.modified {
            hook_indicators.push(format!(
                "in-memory prologue differs from disk at {} offset(s)",
                edr.diff_offsets.len()
            ));
        }
    }
    if want_hookchk && !cfg.json {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_mag("Hook Indicators:"))).ok();
        if hook_indicators.is_empty() {
            writeln!(w, "{}", c.dim("  (none detected)")).ok();
        } else {
            for finding in &hook_indicators {
                writeln!(w, "  {}", c.warn(finding)).ok();
            }
        }
    }

    let xrefs = if cfg.show_xrefs {
        let x = find_xrefs(&insns, &exports, image_base);
        if !cfg.json {
            writeln!(w, "{}", c.bold("\nCall Targets (xrefs out):")).ok();
            if x.is_empty() {
                writeln!(w, "{}", c.dim("  (none)")).ok();
            }
            for r in &x {
                writeln!(w, "  {}", c.cyan(r)).ok();
            }
        }
        x
    } else {
        Vec::new()
    };
    if cfg.show_xrefs {
        progress.tick("collecting call targets");
    }

    let str_refs = if cfg.show_strings {
        let s = find_string_refs(&raw, &pe, &insns);
        if !cfg.json {
            writeln!(w, "{}", c.bold("\nString References:")).ok();
            if s.is_empty() {
                writeln!(w, "{}", c.dim("  (none)")).ok();
            }
            for r in &s {
                writeln!(w, "  {}", c.green(r)).ok();
            }
        }
        s
    } else {
        Vec::new()
    };
    if cfg.show_strings {
        progress.tick("finding string references");
    }

    let api_calls = if cfg.funcs_depth > 0 {
        let calls = collect_api_calls(&insns, &pe, &raw, &symbol_index, image_base);
        if !cfg.json {
            print_api_calls(w, &calls, &resolved_name, c, &raw, &pe, &symbol_index, &exports, arch, image_base, cfg, target_rva);
        }
        progress.tick("building API call map");
        calls
    } else {
        Vec::new()
    };

    let intelli_findings = if want_intelli {
        let findings = analyze_image(&raw, &imports, Some(&insns));
        if !cfg.json {
            print_intelli_findings(w, &findings, c);
        }
        findings
    } else {
        Vec::new()
    };
    if want_intelli && !only_metadata {
        progress.tick("running Intelli triage");
    }

    let recomp_str = if want_recomp {
        let exp = Export { name: resolved_name.clone(), ordinal: 0, rva: target_rva, forward_to: String::new() };
        let s = recomp_c(&insns, &exp, arch, image_base, Some(&symbol_index), cfg);
        if !cfg.c_out.is_empty() {
            std::fs::write(&cfg.c_out, &s)
                .map_err(|e| format!("write C output '{}': {}", cfg.c_out, e))?;
            if !cfg.quiet {
                writeln!(w, "{}", c.ok(&format!("Wrote C reconstruction to {}", cfg.c_out))).ok();
            }
        }
        if cfg.recomp && !cfg.json {
            writeln!(w, "\n{}", c.bold(&c.b_mag("C Reconstruction Preview:"))).ok();
            print_sep(w, c, 80);
            print_c_recomp(w, &s, c);
            print_sep(w, c, 80);
        }
        s
    } else {
        String::new()
    };
    if want_recomp {
        progress.tick("reconstructing C output");
    }

    let cfg_text = if want_cfg {
        let plain = render_cfg_text(&insns, image_base);
        if !cfg.json {
            writeln!(w, "\n{}", c.bold(&c.b_blue("Control Flow Graph:"))).ok();
            print_sep(w, c, 80);
            let colored = render_cfg_colored(&insns, image_base, c);
            write!(w, "{}", colored).ok();
            if !colored.ends_with('\n') {
                writeln!(w).ok();
            }
            print_sep(w, c, 80);
        }
        plain
    } else {
        String::new()
    };
    if want_cfg {
        progress.tick("building control-flow graph");
    }

    progress.finish();
    if cfg.json {
        let result = FuncResult {
            dll:          dll_name,
            dll_path:     dll_path_str,
            function:     resolved_name,
            rva:          format!("0x{:08X}", target_rva),
            va:           format!("0x{:016X}", image_base + target_rva as u64),
            rebased_va:   rebase.map(|base| format!("0x{:016X}", base + target_rva as u64)).unwrap_or_default(),
            image_base:   format!("0x{:016X}", image_base),
            arch:         arch_str,
            entry_point:  format!("0x{:08X}", pe.entry_point),
            size_of_image: format!("0x{:08X}", pe.size_of_image),
            size_of_headers: format!("0x{:08X}", pe.size_of_headers),
            section_alignment: format!("0x{:08X}", pe.section_alignment),
            file_alignment: format!("0x{:08X}", pe.file_alignment),
            checksum: format!("0x{:08X}", pe.checksum),
            subsystem: format!("0x{:04X}", pe.subsystem),
            dll_characteristics: format!("0x{:04X}", pe.dll_characteristics),
            header_corrupt: pe.header_corruption_detected(),
            pe_anomalies: pe.anomalies.iter().map(to_anomaly_json).collect(),
            sections:     pe.sections.iter().map(to_section_json).collect(),
            yara_matches: yara_matches.iter().map(to_yara_json).collect(),
            size_bytes:   func_size_bytes,
            insn_count:   insns.len(),
            pdb_loaded,
            followed_jmp: followed_desc,
            instructions: insns.iter().map(|i| InsnJson {
                rva:     format!("0x{:08X}", i.rva),
                va:      format!("0x{:016X}", i.va),
                rebased_va: rebase.map(|base| format!("0x{:016X}", base + i.rva as u64)).unwrap_or_default(),
                bytes:   i.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                text:    i.text.clone(),
                comment: i.comment.clone(),
            }).collect(),
            xrefs:   xrefs,
            strings: str_refs,
            intelli_findings: if only_metadata { metadata_intelli } else { intelli_findings },
            recomp:  recomp_str,
            cfg:     cfg_text,
            hook_indicators,
            edrchk:  edr_result.as_ref().map(to_edr_json),
            api_calls: api_calls.iter().map(|ac| ApiCallJson {
                rva:        format!("0x{:08X}", ac.rva),
                kind:       ac.kind.clone(),
                target_rva: if ac.target_rva != 0 { format!("0x{:08X}", ac.target_rva) } else { String::new() },
                label:      ac.label.clone(),
                dll:        ac.dll.clone(),
                is_import:  ac.is_import,
                is_indirect: ac.is_indirect,
            }).collect(),
        };
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        writeln!(w, "{}", json).ok();
    }

    Ok(())
}

fn count_dump_steps(cfg: &Config, only_metadata: bool, want_recomp: bool) -> usize {
    let mut total = 5usize;
    if !cfg.no_pdb {
        total += 1;
    }
    if !cfg.yara.is_empty() {
        total += 1;
    }
    if !only_metadata {
        total += 2;
        if cfg.edrchk {
            total += 1;
        }
        if cfg.show_xrefs {
            total += 1;
        }
        if cfg.show_strings {
            total += 1;
        }
        if cfg.funcs_depth > 0 {
            total += 1;
        }
        if want_recomp {
            total += 1;
        }
        if cfg.cfg_view.eq_ignore_ascii_case("text") {
            total += 1;
        }
    }
    if cfg.intelli {
        total += 1;
    }
    total
}

/// 5-color DLL palette — excludes b_yellow/yellow (CALL/JMP), b_mag (Nt*/Zw*),
/// and b_white (named internals) so each role stays visually distinct.
fn dll_palette(c: &Colors, idx: usize, s: &str) -> String {
    match idx % 5 {
        0 => c.cyan(s),
        1 => c.green(s),
        2 => c.magenta(s),
        3 => c.b_cyan(s),
        _ => c.b_blue(s),
    }
}

/// True for Nt*/Zw* Windows native-API names (syscall stubs, lowest UM layer).
fn is_nt_api(label: &str) -> bool {
    (label.starts_with("Nt") || label.starts_with("Zw"))
        && label.as_bytes().get(2).map_or(false, |b| b.is_ascii_uppercase())
}

/// Color the mnemonic: CALL → b_yellow, JMP → yellow  (matches disasm listing).
fn color_kind(kind: &str, c: &Colors) -> String {
    if kind == "call" { c.b_yellow("CALL") } else { c.yellow("JMP") }
}

/// Colour a call target:
///   Nt*/Zw* (any origin) → b_red    — syscall stub, highest visual priority; tag becomes [syscall]
///   IAT import           → dim(dll.dll!) + palette-color(FuncName), one shade per DLL
///   Named internal       → b_white   — resolved known symbol
///   sub_XXXXXXXX         → yellow    — anonymous, address-only
///   Indirect (call rax)  → dim       — unresolvable
fn color_target(
    call: &ApiCall,
    c: &Colors,
    dll_map: &mut std::collections::HashMap<String, usize>,
) -> String {
    let nt = is_nt_api(&call.label);
    if call.is_import {
        let key = call.dll.to_ascii_lowercase();
        let n   = dll_map.len();
        let idx = *dll_map.entry(key).or_insert(n);
        let func = if nt { c.b_red(&call.label) } else { dll_palette(c, idx, &call.label) };
        format!("{}{}", c.dim(&format!("{}!", call.dll)), func)
    } else if call.is_indirect {
        c.dim(&call.label)
    } else if nt {
        c.b_red(&call.label)
    } else if call.label.starts_with("sub_") {
        c.yellow(&call.label)
    } else {
        c.b_white(&call.label)
    }
}

fn print_api_calls(
    w: &mut dyn Write,
    calls: &[ApiCall],
    func_name: &str,
    c: &Colors,
    raw: &[u8],
    pe: &crate::pe::PeFile,
    symbol_index: &crate::symbols::SymbolIndex,
    exports: &[Export],
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_cyan(&format!(
        "API Call Map for {}  [{} call site(s)]:",
        func_name, calls.len()
    )))).ok();

    if calls.is_empty() {
        writeln!(w, "{}", c.dim("  (no CALL/JMP targets found)")).ok();
        return;
    }

    let mut visited = std::collections::HashSet::new();
    visited.insert(root_rva);
    // Shared DLL→color-index map so every level uses the same shade per DLL.
    let mut dll_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    print_calls_recursive(w, calls, c, raw, pe, symbol_index, exports, arch, image_base, cfg, 0, &mut visited, &mut dll_map, "  ");
}

fn print_calls_recursive(
    w: &mut dyn Write,
    calls: &[ApiCall],
    c: &Colors,
    raw: &[u8],
    pe: &crate::pe::PeFile,
    symbol_index: &crate::symbols::SymbolIndex,
    exports: &[Export],
    arch: u32,
    image_base: u64,
    cfg: &Config,
    depth: u32,
    visited: &mut std::collections::HashSet<u32>,
    dll_map: &mut std::collections::HashMap<String, usize>,
    line_prefix: &str,
) {
    let last = calls.len().saturating_sub(1);
    for (i, call) in calls.iter().enumerate() {
        let is_last = i == last;
        let branch   = if is_last { "└──" } else { "├──" };

        let can_recurse = !call.is_import
            && !call.is_indirect
            && call.target_rva != 0
            && depth + 1 < cfg.funcs_depth
            && !visited.contains(&call.target_rva);

        let nt  = is_nt_api(&call.label);
        let tag = match (call.is_import, call.is_indirect, call.kind.as_str(), nt) {
            (true, _, "jmp", true)  => c.dim(" [syscall · tail call]"),
            (true, _, _,    true)   => c.dim(" [syscall]"),
            (true, _, "jmp", false) => c.dim(" [import · tail call]"),
            (true, _, _,    false)  => c.dim(" [import]"),
            (_, true, _, _)         => c.dim(" [indirect]"),
            (_, _, "jmp", _)        => c.dim(" [tail call]"),
            _                       => c.dim(" [internal]"),
        };

        let colored_target = color_target(call, c, dll_map);

        writeln!(w, "{}{} {}  {}  {}{}",
            line_prefix, branch,
            c.dim(&format!("0x{:X}", call.rva)),
            color_kind(&call.kind, c),
            colored_target,
            tag,
        ).ok();

        if can_recurse {
            if let Some(file_off) = pe.rva_to_offset(call.target_rva) {
                visited.insert(call.target_rva);
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(raw, file_off, call.target_rva, arch, image_base, exports, Some(symbol_index), &sub_cfg) {
                    let sub_calls = collect_api_calls(&sub_insns, pe, raw, symbol_index, image_base);
                    if !sub_calls.is_empty() {
                        let child_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        print_calls_recursive(w, &sub_calls, c, raw, pe, symbol_index, exports, arch, image_base, cfg, depth + 1, visited, dll_map, &child_prefix);
                    }
                }
            }
        }
    }
}

fn print_intelli_findings(w: &mut dyn Write, findings: &[IntelliFinding], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_red("Intelli Triage:"))).ok();
    if findings.is_empty() {
        writeln!(w, "{}", c.dim("  (no notable IoC/TTP indicators found)")).ok();
        return;
    }
    for finding in findings {
        writeln!(
            w,
            "  [{}] {} ({}) {}",
            c.b_red(&finding.category),
            c.warn(&finding.rule),
            c.dim(&finding.source).to_string(),
            c.cyan(&finding.value)
        )
        .ok();
    }
}


pub(crate) fn resolve_function(
    func_arg: &str,
    exports: &[Export],
    _pe: &crate::pe::PeFile,
    _raw: &[u8],
    dll_path: &str,
    image_base: u64,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(u32, String, bool), String> {
    if !cfg.at_rva.is_empty() {
        let rva_str = cfg.at_rva.trim_start_matches("0x");
        let rva = u32::from_str_radix(rva_str, 16)
            .map_err(|_| format!("invalid --at value: {}", cfg.at_rva))?;
        let name = if func_arg.is_empty() {
            format!("fn_0x{:08X}", rva)
        } else {
            func_arg.to_owned()
        };
        return Ok((rva, name, false));
    }

    if cfg.ordinal > 0 {
        for e in exports {
            if e.ordinal == cfg.ordinal {
                return Ok((e.rva, e.name.clone(), false));
            }
        }
        return Err(format!("ordinal {} not found in export table", cfg.ordinal));
    }

    for e in exports {
        if e.name == func_arg {
            if !cfg.quiet {
                writeln!(w, "{}", c.ok(&format!(
                    "{} @ RVA 0x{:08X}  (ord {})", e.name, e.rva, e.ordinal
                ))).ok();
            }
            if !e.forward_to.is_empty() && !cfg.no_follow_fwd {
                return Err(format!(
                    "'{}' is a forwarded export → {}\n  use --no-follow-forward or target the correct DLL",
                    func_arg, e.forward_to
                ));
            }
            return Ok((e.rva, e.name.clone(), false));
        }
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
                    "{} @ RVA 0x{:08X}  (from PDB)", func_arg, rva
                ))).ok();
            }
            return Ok((rva, func_arg.to_owned(), true));
        }
    }

    writeln!(w, "\n{} '{}' not found in EAT or PDB symbols", c.err_msg(""), func_arg).ok();
    let lf = func_arg.to_lowercase();
    let suggestions: Vec<&str> = exports.iter()
        .filter(|e| e.name.to_lowercase().contains(&lf))
        .take(8)
        .map(|e| e.name.as_str())
        .collect();
    if !suggestions.is_empty() {
        writeln!(w, "{}", c.warn("Similar exports:")).ok();
        for s in &suggestions {
            writeln!(w, "  {}", c.cyan(s)).ok();
        }
    }
    writeln!(w, "{}", c.dim("  Tip: use --show-eat to list all exports, --ordinal N, or --at <rva>")).ok();
    Err(format!("function '{}' not found", func_arg))
}

fn print_edr_report(w: &mut dyn Write, edr: &EdrCheckResult, c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("EDR / Hook Check:"))).ok();
    if !edr.in_memory_available {
        writeln!(w, "{}", c.warn("In-memory image unavailable for comparison")).ok();
        return;
    }

    if edr.modified {
        writeln!(w, "{}", c.warn(&format!(
            "Prologue mismatch detected: {} differing byte(s) in first {} byte(s)",
            edr.diff_offsets.len(),
            edr.compared_len
        ))).ok();
        writeln!(w, "{}", c.dim(&format!("  Offsets: {}", edr.diff_offsets.iter().map(|o| format!("+0x{:X}", o)).collect::<Vec<_>>().join(", ")))).ok();
    } else {
        writeln!(w, "{}", c.ok(&format!(
            "No prologue modification detected in first {} byte(s)",
            edr.compared_len
        ))).ok();
    }

    writeln!(w, "{}", c.dim(&format!("  Disk: {}", hex_bytes(&edr.disk_bytes)))).ok();
    writeln!(w, "{}", c.dim(&format!("  Mem : {}", hex_bytes(&edr.memory_bytes)))).ok();
    if edr.loaded_from_memory {
        writeln!(w, "{}", c.dim("  Image was loaded for comparison")).ok();
    }
}

fn to_edr_json(edr: &EdrCheckResult) -> EdrJson {
    EdrJson {
        in_memory_available: edr.in_memory_available,
        loaded_for_check: edr.loaded_from_memory,
        compared_len: edr.compared_len,
        modified: edr.modified,
        diff_offsets: edr.diff_offsets.clone(),
        disk_bytes: hex_bytes(&edr.disk_bytes),
        memory_bytes: hex_bytes(&edr.memory_bytes),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

fn to_section_json(section: &PeSection) -> PeSectionJson {
    PeSectionJson {
        name: section.name.clone(),
        rva: format!("0x{:08X}", section.virtual_address),
        virtual_size: format!("0x{:08X}", section.virtual_size),
        raw_offset: format!("0x{:08X}", section.raw_offset),
        raw_size: format!("0x{:08X}", section.raw_size),
        protections: section.protection_string(),
        expected: section.normal_expectation().to_owned(),
        entropy: section.entropy,
        note: section.unusual_protection_reason().unwrap_or_default(),
    }
}

fn to_anomaly_json(anomaly: &PeAnomaly) -> PeAnomalyJson {
    PeAnomalyJson {
        severity: anomaly.severity.clone(),
        kind: anomaly.kind.clone(),
        detail: anomaly.detail.clone(),
    }
}

fn to_yara_json(m: &crate::yara::YaraMatch) -> YaraJson {
    YaraJson {
        rule: m.rule.clone(),
        namespace: m.namespace.clone(),
        tags: m.tags.clone(),
        file: m.file.clone(),
    }
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}
