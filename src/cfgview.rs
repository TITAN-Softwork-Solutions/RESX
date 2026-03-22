use std::collections::{BTreeMap, BTreeSet};

use crate::disasm::{is_ret, Instruction};

#[derive(Debug, Clone)]
pub struct BlockEdge {
    pub kind: &'static str,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_rva: u32,
    pub end_rva: u32,
    pub insns: Vec<Instruction>,
    pub edges: Vec<BlockEdge>,
}

pub fn build_basic_blocks(insns: &[Instruction], image_base: u64) -> Vec<BasicBlock> {
    if insns.is_empty() {
        return Vec::new();
    }

    let mut leaders = BTreeSet::new();
    let mut by_rva = BTreeMap::new();
    leaders.insert(insns[0].rva);

    for (idx, insn) in insns.iter().enumerate() {
        by_rva.insert(insn.rva, idx);
        if (insn.is_jmp || insn.is_jcc) && insn.call_target != 0 {
            leaders.insert(insn.call_target.wrapping_sub(image_base) as u32);
        }
        if (insn.is_jmp || insn.is_jcc || is_ret(insn.iced.mnemonic())) && idx + 1 < insns.len() {
            leaders.insert(insns[idx + 1].rva);
        }
    }

    let leader_list: Vec<u32> = leaders.into_iter().collect();
    let mut blocks = Vec::new();

    for (pos, start_rva) in leader_list.iter().enumerate() {
        let Some(&start_idx) = by_rva.get(start_rva) else { continue };
        let next_leader = leader_list.get(pos + 1).copied();
        let mut end_idx = start_idx;
        while end_idx + 1 < insns.len() {
            if Some(insns[end_idx + 1].rva) == next_leader {
                break;
            }
            end_idx += 1;
        }

        let block_insns = insns[start_idx..=end_idx].to_vec();
        let last = &block_insns[block_insns.len() - 1];
        let mut edges = Vec::new();

        if last.is_jcc {
            if last.call_target != 0 {
                let target_rva = last.call_target.wrapping_sub(image_base) as u32;
                edges.push(BlockEdge {
                    kind: "taken",
                    label: edge_label(last, Some(target_rva)),
                });
            }
            if end_idx + 1 < insns.len() {
                let fallthrough = insns[end_idx + 1].rva;
                edges.push(BlockEdge {
                    kind: "fallthrough",
                    label: format!("fallthrough -> block_{:08X}", fallthrough),
                });
            }
        } else if last.is_jmp {
            if last.call_target != 0 {
                let target_rva = last.call_target.wrapping_sub(image_base) as u32;
                edges.push(BlockEdge {
                    kind: "jump",
                    label: edge_label(last, Some(target_rva)),
                });
            } else {
                edges.push(BlockEdge {
                    kind: "jump",
                    label: format!("indirect jump via {}", last.operands),
                });
            }
        } else if is_ret(last.iced.mnemonic()) {
            edges.push(BlockEdge { kind: "exit", label: "return".to_owned() });
        } else if end_idx + 1 < insns.len() {
            let next_rva = insns[end_idx + 1].rva;
            edges.push(BlockEdge {
                kind: "fallthrough",
                label: format!("fallthrough -> block_{:08X}", next_rva),
            });
        } else {
            edges.push(BlockEdge { kind: "exit", label: "exit".to_owned() });
        }

        blocks.push(BasicBlock {
            start_rva: *start_rva,
            end_rva: last.rva,
            insns: block_insns,
            edges,
        });
    }

    blocks
}

pub fn render_cfg_text(insns: &[Instruction], image_base: u64) -> String {
    let blocks = build_basic_blocks(insns, image_base);
    if blocks.is_empty() {
        return "(no basic blocks)\n".to_owned();
    }

    let mut out = String::new();
    out.push_str(&format!("  blocks: {}\n", blocks.len()));
    out.push_str(&format!("  entry : block_{:08X}\n\n", blocks[0].start_rva));

    for (idx, block) in blocks.iter().enumerate() {
        out.push_str(&format!(
            "block_{:08X}:  [{} insn]  range 0x{:08X}..0x{:08X}\n",
            block.start_rva,
            block.insns.len(),
            block.start_rva,
            block.end_rva
        ));

        for insn in &block.insns {
            let bytes = insn.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            if insn.comment.is_empty() {
                out.push_str(&format!(
                    "    0x{:08X}  {:<26}  {}\n",
                    insn.rva,
                    bytes,
                    insn.text
                ));
            } else {
                out.push_str(&format!(
                    "    0x{:08X}  {:<26}  {}  ; {}\n",
                    insn.rva,
                    bytes,
                    insn.text,
                    insn.comment
                ));
            }
        }

        out.push_str("    edges:\n");
        for edge in &block.edges {
            out.push_str(&format!("      [{}] {}\n", edge.kind, edge.label));
        }

        if idx + 1 < blocks.len() {
            out.push('\n');
        }
    }

    out
}

pub fn detect_static_hook_indicators(insns: &[Instruction], entry_thunk: Option<&crate::thunk::ThunkResolution>) -> Vec<String> {
    let mut findings = Vec::new();

    if let Some(thunk) = entry_thunk {
        findings.push(format!("entry thunk: {}", thunk.desc()));
    }

    if let Some(first) = insns.first() {
        let m = first.iced.mnemonic();
        if first.is_jmp && entry_thunk.is_none() {
            findings.push(format!("entry jump/trampoline at RVA 0x{:08X}", first.rva));
        } else if m == iced_x86::Mnemonic::Call {
            findings.push(format!("entry call trampoline at RVA 0x{:08X}", first.rva));
        }
    }

    findings
}

fn edge_label(insn: &Instruction, target_rva: Option<u32>) -> String {
    if let Some(target_rva) = target_rva {
        if insn.comment.is_empty() {
            format!("{} -> block_{:08X}", insn.mnemonic, target_rva)
        } else {
            format!("{} -> block_{:08X} ({})", insn.mnemonic, target_rva, insn.comment)
        }
    } else if insn.comment.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} ({})", insn.mnemonic, insn.comment)
    }
}
