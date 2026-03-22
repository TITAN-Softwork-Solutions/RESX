use std::collections::{BTreeMap, HashMap};

use crate::pdb::PdbSymbol;
use crate::pe::Export;

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub name: String,
    pub kind: String,
    pub type_name: String,
    pub va: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct SymbolMatch {
    pub symbol: ResolvedSymbol,
    pub displacement: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    exact: HashMap<u64, ResolvedSymbol>,
    ordered: BTreeMap<u64, ResolvedSymbol>,
}

impl SymbolIndex {
    pub fn from_exports_and_pdb(exports: &[Export], pdb_symbols: &[PdbSymbol], image_base: u64) -> Self {
        let mut index = Self::default();

        for e in exports {
            if e.name.is_empty() {
                continue;
            }
            let sym = ResolvedSymbol {
                name: e.name.clone(),
                kind: "function".to_owned(),
                type_name: String::new(),
                va: image_base + e.rva as u64,
                size: 0,
            };
            index.insert(sym);
        }

        for s in pdb_symbols {
            let sym = ResolvedSymbol {
                name: s.name.clone(),
                kind: s.kind.clone(),
                type_name: s.type_name.clone(),
                va: s.va,
                size: s.size,
            };
            index.insert(sym);
        }

        index
    }

    pub fn exact_name(&self, address: u64) -> Option<&str> {
        self.exact.get(&address).map(|s| s.name.as_str())
    }

    pub fn describe(&self, address: u64) -> Option<String> {
        let hit = self.lookup(address)?;
        let mut out = hit.symbol.name.clone();
        if hit.displacement != 0 {
            out.push_str(&format!("+0x{:X}", hit.displacement));
        }
        if !hit.symbol.type_name.is_empty() {
            out.push_str(&format!(" ({})", hit.symbol.type_name));
        } else if hit.symbol.kind == "data" {
            out.push_str(" (data)");
        }
        Some(out)
    }

    pub fn lookup(&self, address: u64) -> Option<SymbolMatch> {
        if let Some(sym) = self.exact.get(&address) {
            return Some(SymbolMatch {
                symbol: sym.clone(),
                displacement: 0,
            });
        }

        let (_, sym) = self.ordered.range(..=address).next_back()?;
        let displacement = address.saturating_sub(sym.va);
        let within = if sym.size > 0 {
            displacement < sym.size
        } else {
            displacement <= 0x100
        };

        if !within {
            return None;
        }

        Some(SymbolMatch {
            symbol: sym.clone(),
            displacement,
        })
    }

    fn insert(&mut self, sym: ResolvedSymbol) {
        let keep_existing = self.exact.get(&sym.va).map(|old| score(old) >= score(&sym)).unwrap_or(false);
        if !keep_existing {
            self.exact.insert(sym.va, sym.clone());
            self.ordered.insert(sym.va, sym);
        }
    }
}

fn score(sym: &ResolvedSymbol) -> u32 {
    let mut score = 0;
    if sym.kind == "data" {
        score += 4;
    }
    if sym.kind == "function" {
        score += 3;
    }
    if !sym.type_name.is_empty() {
        score += 2;
    }
    if !sym.name.starts_with('#') {
        score += 1;
    }
    score
}
