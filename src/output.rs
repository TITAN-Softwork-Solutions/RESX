
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use iced_x86::Mnemonic;

use crate::color::Colors;
use crate::config::Config;
use crate::disasm::{is_jcc, is_jmp, is_ret, is_sys, Instruction};
use crate::pe::{Export, ImportDll, PeAnomaly, PeFile};
use crate::yara::YaraMatch;


pub struct ProgressBar {
    pub total: usize,
    done: AtomicUsize,
    active: bool,
}

impl ProgressBar {
    pub fn new(total: usize, active: bool) -> Self {
        Self { total, active, done: AtomicUsize::new(0) }
    }

    pub fn tick(&self, label: &str) {
        if !self.active { return; }
        let n = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        let w = 30usize;
        let filled = if self.total > 0 { (n * w) / self.total } else { 0 }.min(w);
        let bar = if filled < w {
            format!("{}>{}",  "=".repeat(filled), " ".repeat(w - filled - 1))
        } else {
            "=".repeat(w)
        };
        let label = trunc_label(label, 38);
        eprint!("\r  [{bar}] {:>5}/{:<5}  {:<38}", n, self.total, label);
    }

    pub fn finish(&self) {
        if !self.active { return; }
        eprint!("\r{}\r", " ".repeat(85));
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

fn trunc_label(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        s.to_owned()
    } else {
        chars[chars.len() - max_chars..].iter().collect()
    }
}

pub struct StageProgress {
    total: usize,
    done: usize,
    active: bool,
}

impl StageProgress {
    pub fn new(total: usize, active: bool) -> Self {
        Self { total: total.max(1), done: 0, active }
    }

    pub fn tick(&mut self, label: &str) {
        if !self.active {
            return;
        }
        self.done = (self.done + 1).min(self.total);
        let w = 30usize;
        let filled = ((self.done * w) / self.total).min(w);
        let bar = if filled < w {
            format!("{}>{}", "=".repeat(filled), " ".repeat(w - filled - 1))
        } else {
            "=".repeat(w)
        };
        let label = trunc_label(label, 38);
        eprint!("\r  [{bar}] {:>2}/{:<2}  {:<38}", self.done, self.total, label);
        let _ = std::io::stderr().flush();
    }

    pub fn finish(&self) {
        if !self.active {
            return;
        }
        eprint!("\r{}\r", " ".repeat(85));
        let _ = std::io::stderr().flush();
    }
}


pub fn print_sep(w: &mut dyn Write, c: &Colors, width: usize) {
    writeln!(w, "{}", c.dim(&"─".repeat(width))).ok();
}


fn apply_insn_color(insn: &Instruction, s: &str, c: &Colors) -> String {
    let m = insn.iced.mnemonic();
    if insn.bytes.len() == 1 && insn.bytes[0] == 0xCC { return c.dim(s); }
    if is_ret(m)                                       { return c.b_red(s); }
    if is_sys(m)                                       { return c.b_mag(s); }
    if m == Mnemonic::Call                             { return c.b_yellow(s); }
    if is_jmp(m)                                       { return c.yellow(s); }
    if is_jcc(m)                                       { return c.b_cyan(s); }
    if matches!(m, Mnemonic::Cmp | Mnemonic::Test)    { return c.magenta(s); }
    if matches!(m, Mnemonic::Push | Mnemonic::Pop)    { return c.dim(s); }
    if matches!(m,
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Imul |
        Mnemonic::And | Mnemonic::Or  | Mnemonic::Xor |
        Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar |
        Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not
    )                                                  { return c.green(s); }
    if m == Mnemonic::Nop                              { return c.dim(s); }
    c.b_white(s)
}


pub fn print_insns(w: &mut dyn Write, insns: &[Instruction], cfg: &Config, c: &Colors) {
    let addr_w = if cfg.addr_width == 0 { 8 } else { cfg.addr_width };
    let byte_col_w = if cfg.byte_col_width == 0 { 10 } else { cfg.byte_col_width };

    for insn in insns {
        let addr = c.cyan(&format!("{:0>width$X}", insn.rva, width = addr_w));

        let byte_str = if cfg.show_bytes {
            let hex: Vec<String> = insn.bytes.iter().map(|b| format!("{:02X}", b)).collect();
            let raw = hex.join(" ");
            let pad_w = byte_col_w * 3 - 1;
            let padded = if raw.len() < pad_w {
                format!("{}{}", raw, " ".repeat(pad_w - raw.len()))
            } else {
                raw[..pad_w.min(raw.len())].to_owned()
            };
            format!("{}  ", c.dim(&padded))
        } else {
            String::new()
        };

        let mnem = apply_insn_color(insn, &format!("{:<10}", insn.mnemonic), c);
        let ops  = c.b_white(&insn.operands);

        let mut line = format!("  {}  {}{} {}", addr, byte_str, mnem, ops);
        if !insn.comment.is_empty() {
            line.push_str(&c.dim(&format!("  ; {}", insn.comment)));
        }
        if cfg.show_offsets {
            line.push_str(&c.dim(&format!("  [off: 0x{:X}]", insn.file_off)));
        }
        writeln!(w, "{}", line).ok();
    }
}


pub fn print_eat(w: &mut dyn Write, exports: &[Export], dll_name: &str, c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_yellow(&format!(
        "Export Table: {} ({} exports)", dll_name, exports.len()
    )))).ok();
    print_sep(w, c, 80);
    writeln!(w, "  {:<6}  {:<10}  {}",
        c.bold("ORD"), c.bold("RVA"), c.bold("NAME")).ok();
    print_sep(w, c, 80);
    for e in exports {
        let suffix = if !e.forward_to.is_empty() {
            c.dim(&format!("  → {} [fwd]", e.forward_to))
        } else {
            String::new()
        };
        writeln!(w, "  {:<6}  0x{:08X}  {}{}",
            e.ordinal, e.rva, c.b_white(&e.name), suffix).ok();
    }
    print_sep(w, c, 80);
}


pub fn print_iat(w: &mut dyn Write, imps: &[ImportDll], dll_name: &str, c: &Colors) {
    let total: usize = imps.iter().map(|d| d.entries.len()).sum();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue(&format!(
        "Import Table: {} ({} DLLs, {} imports)", dll_name, imps.len(), total
    )))).ok();
    for d in imps {
        print_sep(w, c, 80);
        writeln!(w, "  {} {}", c.bold(&c.cyan("DLL:")), c.b_yellow(&d.dll)).ok();
        for e in &d.entries {
            let hint = if !e.by_ord {
                c.dim(&format!("  (hint: 0x{:03X})", e.hint))
            } else {
                String::new()
            };
            writeln!(w, "    {}{}", c.b_white(&e.name), hint).ok();
        }
    }
    print_sep(w, c, 80);
}

pub fn print_sections(w: &mut dyn Write, pe: &PeFile, c: &Colors) {
    const WIDTH: usize = 126;
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("Sections:"))).ok();
    writeln!(w, "{}", c.dim(&"-".repeat(WIDTH))).ok();
    writeln!(
        w,
        "  {:<10} {:<10} {:<10} {:<10} {:<4} {:<22} {:<22} {:<8} {}",
        c.bold("NAME"),
        c.bold("RVA"),
        c.bold("VSIZE"),
        c.bold("RAW"),
        c.bold("TAG"),
        c.bold("PROTECTION"),
        c.bold("EXPECTED"),
        c.bold("ENTROPY"),
        c.bold("NOTES")
    ).ok();
    writeln!(w, "{}", c.dim(&"-".repeat(WIDTH))).ok();
    for s in &pe.sections {
        let notes = s.unusual_protection_reason().unwrap_or_default();
        let notes = if notes.is_empty() { String::new() } else { c.warn(&notes) };
        writeln!(
            w,
            "  {:<10} 0x{:08X} 0x{:08X} 0x{:08X} {:<4} {:<22} {:<22} {:<8.3} {}",
            c.b_white(&s.name),
            s.virtual_address,
            s.virtual_size,
            s.raw_size,
            s.protection_string(),
            s.protection_name(),
            s.normal_expectation_name(),
            s.entropy,
            notes
        ).ok();
    }
    writeln!(w, "{}", c.dim(&"-".repeat(WIDTH))).ok();
}

pub fn print_pe_anomalies(w: &mut dyn Write, anomalies: &[PeAnomaly], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_mag("PE Header / Layout Check:"))).ok();
    if anomalies.is_empty() {
        writeln!(w, "{}", c.ok("No header or section anomalies detected")).ok();
        return;
    }
    for a in anomalies {
        let sev = match a.severity.as_str() {
            "high" => c.b_red("HIGH"),
            "warn" => c.b_yellow("WARN"),
            _ => c.cyan("INFO"),
        };
        writeln!(w, "  [{}] {}: {}", sev, c.b_white(&a.kind), a.detail).ok();
    }
}

pub fn print_yara_matches(w: &mut dyn Write, matches: &[YaraMatch], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_red("YARA Matches:"))).ok();
    if matches.is_empty() {
        writeln!(w, "{}", c.dim("  (none)")).ok();
        return;
    }
    for m in matches {
        let prefix = if m.namespace.is_empty() {
            m.rule.clone()
        } else {
            format!("{}:{}", m.namespace, m.rule)
        };
        let tags = if m.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", m.tags.join(", "))
        };
        writeln!(w, "  {}{}  {}", c.b_yellow(&prefix), tags, c.dim(&m.file)).ok();
    }
}


pub fn print_c_recomp(w: &mut dyn Write, source: &str, c: &Colors) {
    for line in source.lines() {
        writeln!(w, "{}", highlight_c_line(line, c)).ok();
    }
}

fn highlight_c_line(line: &str, c: &Colors) -> String {
    let (code, comment) = if let Some(idx) = line.find("//") {
        (&line[..idx], Some(&line[idx..]))
    } else {
        (line, None)
    };

    let mut out = String::new();
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_ascii_alphanumeric() || ch == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            out.push_str(&highlight_c_token(&token, c));
            continue;
        }
        if ch == '"' {
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let token: String = chars[start..i.min(chars.len())].iter().collect();
            out.push_str(&c.green(&token));
            continue;
        }
        out.push(ch);
        i += 1;
    }

    if let Some(comment) = comment {
        out.push_str(&c.dim(comment));
    }

    out
}

fn highlight_c_token(token: &str, c: &Colors) -> String {
    if matches!(
        token,
        "if" | "else" | "return" | "goto" | "void" | "unsigned" | "struct"
    ) {
        return c.b_mag(token);
    }
    if matches!(
        token,
        "NTSTATUS" | "__fastcall" | "__stdcall" | "PUSH" | "POP" | "__syscall" | "__sysenter" | "__interrupt"
    ) {
        return c.b_cyan(token);
    }
    if token.starts_with("label_") {
        return c.b_yellow(token);
    }
    if token.starts_with("0x") || token.chars().all(|ch| ch.is_ascii_digit()) {
        return c.yellow(token);
    }
    token.to_owned()
}
