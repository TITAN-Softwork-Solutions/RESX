use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use rayon::prelude::*;

use crate::color::Colors;
use crate::follow_scan::{scan_dll_for_callers, Caller, FollowScanConfig};

#[derive(Debug, Clone)]
pub struct FuncRef {
    pub dll: String,
    pub dll_path: String,
    pub name: String,
    pub rva: u32,
    pub va: u64,
    pub is_internal: bool,
}

impl FuncRef {
    pub fn key(&self) -> String {
        format!("{}!{}", self.dll.to_lowercase(), self.name)
    }
    pub fn display(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct CallNode {
    pub func: FuncRef,
    pub depth: usize,
    pub sites: Vec<crate::follow_scan::CallSite>,
    pub callers: Vec<CallNode>,
    pub truncated: bool,
}

pub struct TraceCtx<'a> {
    pub cfg: &'a FollowScanConfig,
    pub scan_paths: &'a [PathBuf],
    pub target_arch: u32,
    pub visited: Mutex<std::collections::HashMap<String, bool>>,
    pub total: Mutex<usize>,
}

impl<'a> TraceCtx<'a> {
    fn mark_visited(&self, key: &str) -> bool {
        let mut v = self.visited.lock().unwrap();
        if v.contains_key(key) { return false; }
        v.insert(key.to_owned(), true);
        true
    }

    fn check_total(&self) -> bool {
        self.cfg.max_total > 0 && *self.total.lock().unwrap() >= self.cfg.max_total
    }

    fn inc_total(&self) {
        *self.total.lock().unwrap() += 1;
    }
}

fn scan_all_dlls(target: &FuncRef, ctx: &TraceCtx<'_>, pb: &crate::output::ProgressBar) -> Vec<Caller> {
    let mut all: Vec<Caller> = ctx.scan_paths
        .par_iter()
        .flat_map_iter(|path| {
            let callers = scan_dll_for_callers(path, target, ctx.target_arch, ctx.cfg);
            pb.tick(&path.file_name().unwrap_or_default().to_string_lossy());
            callers
        })
        .collect();

    if !ctx.cfg.filter_dll.is_empty() {
        let f = ctx.cfg.filter_dll.to_lowercase();
        all.retain(|c| c.func.dll.to_lowercase().contains(&f));
    }
    all
}

pub fn build_call_tree(target: FuncRef, depth: usize, ctx: &TraceCtx<'_>, w: &mut dyn Write, c: &Colors) -> CallNode {
    let mut node = CallNode { func: target.clone(), depth, sites: Vec::new(), callers: Vec::new(), truncated: false };
    if depth >= ctx.cfg.depth || ctx.check_total() {
        node.truncated = true;
        return node;
    }

    if !ctx.cfg.quiet {
        let msg = if depth == 0 {
            format!("Scanning {} files for callers of {}!{}...", ctx.scan_paths.len(), target.dll, target.name)
        } else {
            format!("[depth {}] Finding callers of {}!{}...", depth, target.dll, target.display())
        };
        writeln!(w, "{}", c.info(&msg)).ok();
    }

    let pb = crate::output::ProgressBar::new(ctx.scan_paths.len(), c.on && !ctx.cfg.quiet);
    let mut callers = scan_all_dlls(&target, ctx, &pb);
    pb.finish();
    if !ctx.cfg.quiet {
        writeln!(w, "{}", c.dim(&format!("  -> {} caller(s) found", callers.len()))).ok();
    }

    if ctx.cfg.max_callers > 0 && callers.len() > ctx.cfg.max_callers {
        callers.truncate(ctx.cfg.max_callers);
        node.truncated = true;
    }

    for caller in callers {
        let key = caller.func.key();
        ctx.inc_total();
        let mut child = CallNode {
            func: caller.func.clone(),
            depth: depth + 1,
            sites: caller.sites,
            callers: Vec::new(),
            truncated: false,
        };

        if ctx.mark_visited(&key) {
            let sub = build_call_tree(caller.func, depth + 1, ctx, w, c);
            child.callers = sub.callers;
            child.truncated = sub.truncated;
        } else {
            child.truncated = true;
        }

        node.callers.push(child);
    }

    node
}
