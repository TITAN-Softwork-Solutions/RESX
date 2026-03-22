use iced_x86::{Mnemonic, OpKind, Register};

use crate::disasm::{is_jcc, Instruction};
use crate::pe::Export;
use crate::symbols::SymbolIndex;

fn fmt_op(instr: &iced_x86::Instruction, op_idx: u32, image_base: u64, symbols: Option<&SymbolIndex>) -> String {
    if op_idx >= instr.op_count() {
        return String::new();
    }
    match instr.op_kind(op_idx) {
        OpKind::Register => format!("{:?}", instr.op_register(op_idx)).to_lowercase(),
        OpKind::Immediate64 => {
            let v = instr.immediate64();
            if v >= image_base {
                if let Some(desc) = symbols.and_then(|idx| idx.describe(v)) {
                    return desc;
                }
            }
            format!("0x{:X}", v)
        }
        OpKind::Immediate32 => {
            let v = instr.immediate32() as u64;
            if v >= image_base {
                if let Some(desc) = symbols.and_then(|idx| idx.describe(v)) {
                    return desc;
                }
            }
            format!("0x{:X}", v)
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            let v = instr.immediate(op_idx);
            if v == 0 {
                "0".to_owned()
            } else if (v as i64) < 0 {
                format!("-0x{:X}", (-(v as i64)) as u64)
            } else {
                format!("0x{:X}", v)
            }
        }
        OpKind::Memory => {
            if let Some(addr) = absolute_memory_address(instr) {
                if addr >= image_base {
                    if let Some(desc) = symbols.and_then(|idx| idx.describe(addr)) {
                        return format!("*({})", desc);
                    }
                }
            }
            let base = instr.memory_base();
            let idx = instr.memory_index();
            let scale = instr.memory_index_scale();
            let disp = instr.memory_displacement64() as i64;

            let seg = if instr.memory_segment() != Register::None && instr.memory_segment() != Register::DS {
                format!("{:?}:", instr.memory_segment()).to_lowercase() + ":"
            } else {
                String::new()
            };

            let base_s = if base != Register::None && base != Register::RIP {
                format!("{:?}", base).to_lowercase()
            } else {
                String::new()
            };

            let idx_s = if idx != Register::None {
                let i = format!("{:?}", idx).to_lowercase();
                if scale > 1 { format!("{}*{}", i, scale) } else { i }
            } else {
                String::new()
            };

            let disp_s = if disp > 0 {
                format!("+0x{:X}", disp)
            } else if disp < 0 {
                format!("-0x{:X}", (-disp) as u64)
            } else {
                String::new()
            };

            let mut inner = base_s;
            if !idx_s.is_empty() {
                if !inner.is_empty() {
                    inner.push('+');
                }
                inner.push_str(&idx_s);
            }
            inner.push_str(&disp_s);
            if inner.is_empty() {
                inner = "0".to_owned();
            }

            format!("{}*({})", seg, inner)
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            format!("0x{:X}", instr.near_branch_target())
        }
        _ => "?".to_owned(),
    }
}

fn jcc_condition(m: Mnemonic, prev_cmp: Option<&iced_x86::Instruction>, image_base: u64, symbols: Option<&SymbolIndex>) -> String {
    let Some(cmp_instr) = prev_cmp else {
        return match m {
            Mnemonic::Je => "ZF".to_owned(),
            Mnemonic::Jne => "!ZF".to_owned(),
            Mnemonic::Js => "SF".to_owned(),
            Mnemonic::Jns => "!SF".to_owned(),
            Mnemonic::Jo => "OF".to_owned(),
            Mnemonic::Jno => "!OF".to_owned(),
            _ => format!("{:?}", m),
        };
    };

    let a = fmt_op(cmp_instr, 0, image_base, symbols);
    let b = fmt_op(cmp_instr, 1, image_base, symbols);
    let is_self_test = cmp_instr.mnemonic() == Mnemonic::Test && a == b;
    match m {
        Mnemonic::Je if is_self_test => format!("{} == 0", a),
        Mnemonic::Jne if is_self_test => format!("{} != 0", a),
        Mnemonic::Je => format!("{} == {}", a, b),
        Mnemonic::Jne => format!("{} != {}", a, b),
        Mnemonic::Ja => format!("(unsigned){} > (unsigned){}", a, b),
        Mnemonic::Jae => format!("(unsigned){} >= (unsigned){}", a, b),
        Mnemonic::Jb => format!("(unsigned){} < (unsigned){}", a, b),
        Mnemonic::Jbe => format!("(unsigned){} <= (unsigned){}", a, b),
        Mnemonic::Jg => format!("{} > {}", a, b),
        Mnemonic::Jge => format!("{} >= {}", a, b),
        Mnemonic::Jl => format!("{} < {}", a, b),
        Mnemonic::Jle => format!("{} <= {}", a, b),
        Mnemonic::Js => format!("{} < 0", a),
        Mnemonic::Jns => format!("{} >= 0", a),
        _ => format!("{:?}", m),
    }
}

pub fn recomp_c(insns: &[Instruction], exp: &Export, arch: u32, image_base: u64, symbols: Option<&SymbolIndex>, _cfg: &crate::config::Config) -> String {
    if insns.is_empty() {
        return "// No instructions to reconstruct.".to_owned();
    }

    let mut sb = String::new();
    let mut jump_targets: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for insn in insns {
        if (insn.is_jmp || insn.is_jcc) && insn.call_target != 0 {
            let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
            jump_targets.insert(t_rva);
        }
    }

    let (cc, param_regs): (&str, &[&str]) = if arch == 64 {
        ("__fastcall", &["rcx", "rdx", "r8", "r9"])
    } else {
        ("__stdcall", &[])
    };

    let mut used_params = 0usize;
    for insn in insns {
        for op_idx in 0..insn.iced.op_count() {
            if insn.iced.op_kind(op_idx) == OpKind::Register {
                let reg_name = format!("{:?}", insn.iced.op_register(op_idx)).to_lowercase();
                for (i, &pr) in param_regs.iter().enumerate() {
                    if reg_name == pr && i >= used_params {
                        used_params = i + 1;
                    }
                }
            }
        }
    }
    if used_params == 0 && arch == 32 {
        used_params = 4;
    }

    sb.push_str("// ------------------------------------------------------------\n");
    sb.push_str("// C Reconstruction Preview\n");
    sb.push_str(&format!("// Source: {}\n", exp.name));
    sb.push_str(&format!("// RVA: 0x{:08X}\n", exp.rva));
    sb.push_str(&format!("// Arch: x{}\n", arch));
    let size_bytes = {
        let last = insns.last().unwrap();
        (last.rva - insns[0].rva) as usize + last.bytes.len()
    };
    sb.push_str(&format!("// Size: ~{} bytes, {} instructions\n\n", size_bytes, insns.len()));

    let ret_type = "NTSTATUS";
    sb.push_str(&format!("{} {} {}(\n", ret_type, cc, exp.name));
    if used_params == 0 {
        sb.push_str("    void\n");
    } else if arch == 64 {
        for i in 0..used_params {
            let sep = if i + 1 == used_params { "" } else { "," };
            sb.push_str(&format!("    void* param_{}{} \n", i + 1, sep));
        }
    } else {
        for i in 0..used_params {
            let sep = if i + 1 == used_params { "" } else { "," };
            sb.push_str(&format!("    void* param_{}{} \n", i + 1, sep));
        }
    }
    sb.push_str(") {\n");

    let mut prev_cmp: Option<&Instruction> = None;

    for insn in insns {
        if jump_targets.contains(&insn.rva) {
            sb.push_str(&format!("\nlabel_{:08X}:\n", insn.rva));
        }

        let orig_asm = if insn.comment.is_empty() {
            insn.text.clone()
        } else {
            format!("{}  ; {}", insn.text, insn.comment)
        };

        let a0 = fmt_op(&insn.iced, 0, image_base, symbols);
        let a1 = fmt_op(&insn.iced, 1, image_base, symbols);
        let m = insn.iced.mnemonic();

        let stmt = match m {
            Mnemonic::Mov => format!("{} = {};", a0, a1),
            Mnemonic::Lea => format!("{} = &{};", a0, a1),
            Mnemonic::Xor => {
                if a0 == a1 { format!("{} = 0;", a0) } else { format!("{} ^= {};", a0, a1) }
            }
            Mnemonic::Add => format!("{} += {};", a0, a1),
            Mnemonic::Sub => format!("{} -= {};", a0, a1),
            Mnemonic::And => format!("{} &= {};", a0, a1),
            Mnemonic::Or => format!("{} |= {};", a0, a1),
            Mnemonic::Shl => format!("{} <<= {};", a0, a1),
            Mnemonic::Shr => format!("{} >>= {};", a0, a1),
            Mnemonic::Sar => format!("{} >>= {};", a0, a1),
            Mnemonic::Not => format!("{} = ~{};", a0, a0),
            Mnemonic::Neg => format!("{} = -{};", a0, a0),
            Mnemonic::Inc => format!("{}++;", a0),
            Mnemonic::Dec => format!("{}--;", a0),
            Mnemonic::Imul | Mnemonic::Mul => {
                if insn.iced.op_count() > 1 { format!("{} *= {};", a0, a1) } else { format!("mul({});", a0) }
            }
            Mnemonic::Push => format!("PUSH({});", a0),
            Mnemonic::Pop => format!("{} = POP();", a0),
            Mnemonic::Call => {
                let target = if !insn.comment.is_empty() {
                    insn.comment.clone()
                } else if insn.call_target != 0 {
                    format!("fn_0x{:X}", insn.call_target)
                } else {
                    a0.clone()
                };
                format!("result = {}();", target)
            }
            _ if crate::disasm::is_ret(m) => {
                if arch == 64 { "return rax;".to_owned() } else { "return eax;".to_owned() }
            }
            Mnemonic::Jmp => {
                if insn.call_target != 0 {
                    let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
                    if jump_targets.contains(&t_rva) {
                        format!("goto label_{:08X};", t_rva)
                    } else {
                        format!("return {}();", insn.comment)
                    }
                } else {
                    format!("goto *{};", a0)
                }
            }
            Mnemonic::Cmp | Mnemonic::Test => format!("/* compare {}, {} */", a0, a1),
            Mnemonic::Nop => "/* nop */".to_owned(),
            Mnemonic::Syscall => {
                let reg = if arch == 64 { "rax" } else { "eax" };
                format!("__syscall({});", reg)
            }
            Mnemonic::Int => {
                let imm = insn.iced.immediate(0);
                format!("__interrupt(0x{:X});", imm)
            }
            Mnemonic::Sysenter => "__sysenter();".to_owned(),
            _ if is_jcc(m) => {
                let cond = jcc_condition(m, prev_cmp.map(|c| &c.iced), image_base, symbols);
                if insn.call_target != 0 {
                    let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
                    format!("if ({}) goto label_{:08X};", cond, t_rva)
                } else {
                    format!("if ({}) goto *{};", cond, a0)
                }
            }
            _ => format!("/* {} */", orig_asm),
        };

        if matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
            prev_cmp = Some(insn);
        } else if !is_jcc(m) {
            prev_cmp = None;
        }

        const STMT_WIDTH: usize = 52;
        let pad = if stmt.len() < STMT_WIDTH { STMT_WIDTH - stmt.len() } else { 0 };
        sb.push_str(&format!("    {}{}  // {}\n", stmt, " ".repeat(pad), orig_asm));
    }

    sb.push_str("}\n");
    sb
}

fn absolute_memory_address(instr: &iced_x86::Instruction) -> Option<u64> {
    if instr.memory_base() == Register::RIP || instr.memory_base() == Register::EIP {
        return Some(instr.ip_rel_memory_address());
    }
    if instr.memory_base() == Register::None && instr.memory_index() == Register::None {
        let disp = instr.memory_displacement64();
        if disp != 0 {
            return Some(disp);
        }
    }
    None
}
