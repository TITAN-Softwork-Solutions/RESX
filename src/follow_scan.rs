use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::pe::{attribute_to_func, find_iat_slot_va, parse_pe, read_exports};

#[derive(Debug, Clone)]
pub struct FollowScanConfig {
    pub extra_paths: Vec<String>,
    pub no_cwd: bool,
    pub no_path_env: bool,
    pub scan_dirs: Vec<String>,
    pub scan_dlls: Vec<String>,
    pub no_system: bool,
    pub no_wow64: bool,
    pub scan_exe: bool,
    pub include: String,
    pub exclude: String,
    pub max_dll_bytes: u64,
    pub workers: usize,
    pub arch: String,
    pub depth: usize,
    pub max_callers: usize,
    pub max_total: usize,
    pub filter_dll: String,
    pub show_rva: bool,
    pub show_site: bool,
    pub quiet: bool,
}

impl FollowScanConfig {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            extra_paths: cfg.extra_paths.clone(),
            no_cwd: cfg.no_cwd,
            no_path_env: cfg.no_path,
            scan_dirs: cfg.scan_dirs.clone(),
            scan_dlls: cfg.scan_dlls.clone(),
            no_system: cfg.no_system,
            no_wow64: cfg.no_wow64,
            scan_exe: cfg.scan_exe,
            include: cfg.include.clone(),
            exclude: cfg.exclude.clone(),
            max_dll_bytes: cfg.max_dll_mb * 1024 * 1024,
            workers: cfg.workers,
            arch: cfg.arch.clone(),
            depth: cfg.depth,
            max_callers: cfg.max_callers,
            max_total: cfg.max_total,
            filter_dll: cfg.filter_dll.clone(),
            show_rva: cfg.show_rva,
            show_site: cfg.show_site,
            quiet: cfg.quiet,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub rva: u32,
    pub pattern: String,
}

#[derive(Debug, Clone)]
pub struct Caller {
    pub func: crate::follow_trace::FuncRef,
    pub sites: Vec<CallSite>,
}

pub fn system_dirs(cfg: &FollowScanConfig) -> Vec<PathBuf> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let mut dirs = Vec::new();
    if !cfg.no_system {
        dirs.push(PathBuf::from(&windir).join("System32"));
        dirs.push(PathBuf::from(&windir).join("Sysnative"));
    }
    if !cfg.no_wow64 {
        dirs.push(PathBuf::from(&windir).join("SysWOW64"));
    }
    dirs
}

pub fn find_target_dll(name: &str, cfg: &FollowScanConfig) -> Result<PathBuf, String> {
    if name.contains('/') || name.contains('\\') {
        let p = PathBuf::from(name);
        if p.exists() {
            return p.canonicalize().map_err(|e| e.to_string());
        }
        return Err(format!("not found: {}", name));
    }
    let base = if Path::new(name).extension().is_none() { format!("{}.dll", name) } else { name.to_owned() };

    let mut dirs: Vec<PathBuf> = cfg.extra_paths.iter().map(PathBuf::from).collect();
    if !cfg.no_cwd {
        if let Ok(d) = std::env::current_dir() {
            dirs.push(d);
        }
    }
    dirs.extend(system_dirs(cfg));
    if !cfg.no_path_env {
        if let Ok(path) = std::env::var("PATH") {
            for p in std::env::split_paths(&path) {
                if !p.as_os_str().is_empty() {
                    dirs.push(p);
                }
            }
        }
    }

    for dir in &dirs {
        let c = dir.join(&base);
        if c.exists() {
            return c.canonicalize().map_err(|e| e.to_string());
        }
    }
    Err(format!("'{}' not found in system32, SysWOW64, PATH; use --path or provide full path", name))
}

pub fn build_scan_list(cfg: &FollowScanConfig, target_dll: &Path) -> Vec<PathBuf> {
    if is_external_driver_target(target_dll) && cfg.scan_dirs.is_empty() && cfg.scan_dlls.is_empty() {
        return vec![target_dll.to_path_buf()];
    }

    let exts: Vec<&str> = if cfg.scan_exe { vec!["dll", "exe"] } else { vec!["dll"] };
    let mut seen = std::collections::HashSet::new();
    let mut paths = Vec::new();

    let add_dir = |dir: &Path, paths: &mut Vec<PathBuf>, seen: &mut std::collections::HashSet<String>,
                   exts: &[&str], cfg: &FollowScanConfig| {
        let Ok(entries) = std::fs::read_dir(dir) else { return; };
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !exts.iter().any(|e| e.eq_ignore_ascii_case(ext)) { continue; }

            let abs = match p.canonicalize() { Ok(a) => a, Err(_) => continue };
            let low = abs.to_string_lossy().to_lowercase();
            if seen.contains(&low) { continue; }

            if cfg.max_dll_bytes > 0 {
                if let Ok(m) = abs.metadata() {
                    if m.len() > cfg.max_dll_bytes { continue; }
                }
            }

            let base = abs.file_name().unwrap_or_default().to_string_lossy();
            if !cfg.include.is_empty() && !glob_match(&cfg.include, &base) { continue; }
            if !cfg.exclude.is_empty() && glob_match(&cfg.exclude, &base) { continue; }

            seen.insert(low);
            paths.push(abs);
        }
    };

    for dir in system_dirs(cfg) { add_dir(&dir, &mut paths, &mut seen, &exts, cfg); }
    for dir in cfg.scan_dirs.iter().map(PathBuf::from) { add_dir(&dir, &mut paths, &mut seen, &exts, cfg); }
    for dll_arg in &cfg.scan_dlls {
        if let Ok(p) = find_target_dll(dll_arg, cfg) {
            let low = p.to_string_lossy().to_lowercase();
            if seen.insert(low) { paths.push(p); }
        }
    }

    let target_low = target_dll.to_string_lossy().to_lowercase();
    if !paths.iter().any(|p| p.to_string_lossy().to_lowercase() == target_low) {
        paths.push(target_dll.to_path_buf());
    }
    paths.sort();
    paths
}

fn is_external_driver_target(target: &Path) -> bool {
    let is_sys = target.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("sys"))
        .unwrap_or(false);
    if !is_sys {
        return false;
    }

    let lower = target.to_string_lossy().to_ascii_lowercase();
    !(lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\sysnative\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower.contains("\\windows\\system32\\drivers\\"))
}

fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    glob_inner(&p, &n)
}

fn glob_inner(p: &[char], n: &[char]) -> bool {
    match (p.first(), n.first()) {
        (None, None) => true,
        (Some(&'*'), _) => glob_inner(&p[1..], n) || (!n.is_empty() && glob_inner(p, &n[1..])),
        (Some(&'?'), Some(_)) => glob_inner(&p[1..], &n[1..]),
        (Some(a), Some(b)) if a == b => glob_inner(&p[1..], &n[1..]),
        _ => false,
    }
}

const SCN_CODE: u32 = 0x0000_0020;
const SCN_EXEC: u32 = 0x2000_0000;

pub fn find_iat_call_sites(raw: &[u8], pe: &crate::pe::PeFile, iat_slot_va: u64) -> Vec<CallSite> {
    let mut sites = Vec::new();
    for s in &pe.sections {
        if s.characteristics & (SCN_CODE | SCN_EXEC) == 0 { continue; }
        if s.raw_offset == 0 || s.raw_size == 0 { continue; }
        let start = s.raw_offset as usize;
        let end = (start + s.raw_size as usize).min(raw.len());
        if start >= end { continue; }
        let sec = &raw[start..end];
        let sec_va_base = pe.image_base + s.virtual_address as u64;

        if pe.arch == 64 {
            for i in 0..sec.len().saturating_sub(5) {
                let b0 = sec[i];
                let b1 = sec.get(i + 1).copied().unwrap_or(0);
                let is_call = b0 == 0xFF && b1 == 0x15;
                let is_jmp = b0 == 0xFF && b1 == 0x25;
                if (!is_call && !is_jmp) || i + 6 > sec.len() { continue; }
                let rel32 = i32::from_le_bytes(sec[i + 2..i + 6].try_into().unwrap());
                let instr_va = sec_va_base + i as u64;
                let target = (instr_va as i64 + 6 + rel32 as i64) as u64;
                if target != iat_slot_va { continue; }
                sites.push(CallSite {
                    rva: s.virtual_address + i as u32,
                    pattern: if is_call { "CALL [IAT]" } else { "JMP [IAT]" }.to_owned(),
                });
            }
        } else {
            let slot32 = iat_slot_va as u32;
            for i in 0..sec.len().saturating_sub(5) {
                let b0 = sec[i];
                let b1 = sec.get(i + 1).copied().unwrap_or(0);
                let is_call = b0 == 0xFF && b1 == 0x15;
                let is_jmp = b0 == 0xFF && b1 == 0x25;
                if (!is_call && !is_jmp) || i + 6 > sec.len() { continue; }
                let abs32 = u32::from_le_bytes(sec[i + 2..i + 6].try_into().unwrap());
                if abs32 != slot32 { continue; }
                sites.push(CallSite {
                    rva: s.virtual_address + i as u32,
                    pattern: if is_call { "CALL [IAT]" } else { "JMP [IAT]" }.to_owned(),
                });
            }
        }
    }
    sites
}

pub fn find_direct_call_sites(raw: &[u8], pe: &crate::pe::PeFile, target_va: u64) -> Vec<CallSite> {
    let mut sites = Vec::new();
    for s in &pe.sections {
        if s.characteristics & (SCN_CODE | SCN_EXEC) == 0 { continue; }
        if s.raw_offset == 0 || s.raw_size == 0 { continue; }
        let start = s.raw_offset as usize;
        let end = (start + s.raw_size as usize).min(raw.len());
        if start >= end { continue; }
        let sec = &raw[start..end];
        let sec_va_base = pe.image_base + s.virtual_address as u64;

        for i in 0..sec.len().saturating_sub(4) {
            let b = sec[i];
            if b != 0xE8 && b != 0xE9 { continue; }
            if i + 5 > sec.len() { continue; }
            let rel32 = i32::from_le_bytes(sec[i + 1..i + 5].try_into().unwrap());
            let instr_va = sec_va_base + i as u64;
            let calc_target = (instr_va as i64 + 5 + rel32 as i64) as u64;
            if calc_target != target_va { continue; }
            sites.push(CallSite {
                rva: s.virtual_address + i as u32,
                pattern: if b == 0xE8 { "CALL rel32" } else { "JMP rel32 (tail)" }.to_owned(),
            });
        }
    }
    sites
}

pub fn scan_dll_for_callers(
    dll_path: &Path,
    target: &crate::follow_trace::FuncRef,
    target_arch: u32,
    cfg: &FollowScanConfig,
) -> Vec<Caller> {
    let Ok(raw) = std::fs::read(dll_path) else { return Vec::new() };
    let Ok(pe) = parse_pe(&raw) else { return Vec::new() };

    let arch_match = match cfg.arch.as_str() {
        "x86" | "32" => pe.arch == 32,
        "x64" | "64" => pe.arch == 64,
        _ => target_arch == 0 || pe.arch == target_arch,
    };
    if !arch_match { return Vec::new(); }

    let image_base = pe.image_base;
    let exports = read_exports(&pe, &raw);
    let dll_base = dll_path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    let target_base = Path::new(&target.dll_path)
        .file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    let is_same_dll = dll_base == target_base;

    let mut all_sites = Vec::new();
    if !is_same_dll {
        if let Some(slot_va) = find_iat_slot_va(&pe, &raw, &target.dll_path, &target.name) {
            all_sites.extend(find_iat_call_sites(&raw, &pe, slot_va));
        }
    } else {
        all_sites.extend(find_direct_call_sites(&raw, &pe, target.va));
    }
    if all_sites.is_empty() { return Vec::new(); }

    let dll_name = dll_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let mut map: std::collections::HashMap<u32, (crate::follow_trace::FuncRef, Vec<CallSite>)> =
        std::collections::HashMap::new();

    for site in all_sites {
        let (owner_rva, func_ref) = if let Some(e) = attribute_to_func(site.rva, &exports) {
            (e.rva, crate::follow_trace::FuncRef {
                dll: dll_name.clone(),
                dll_path: dll_path_str.clone(),
                name: e.name.clone(),
                rva: e.rva,
                va: image_base + e.rva as u64,
                is_internal: false,
            })
        } else {
            (site.rva, crate::follow_trace::FuncRef {
                dll: dll_name.clone(),
                dll_path: dll_path_str.clone(),
                name: format!("sub_{:08X}", site.rva),
                rva: site.rva,
                va: image_base + site.rva as u64,
                is_internal: true,
            })
        };

        let entry = map.entry(owner_rva).or_insert_with(|| (func_ref, Vec::new()));
        entry.1.push(site);
    }

    let mut result: Vec<Caller> = map.into_values().map(|(f, s)| Caller { func: f, sites: s }).collect();
    result.sort_by(|a, b| a.func.key().cmp(&b.func.key()));
    result
}
