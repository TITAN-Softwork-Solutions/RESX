
#[cfg(windows)]
mod win {
    use std::ffi::{c_void, CString};
    use std::collections::HashSet;
    use std::path::Path;
    use std::slice;

    const DEFAULT_MS_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";


    type FnSymInitialize    = unsafe extern "system" fn(*mut c_void, *const u8, i32) -> i32;
    type FnSymCleanup       = unsafe extern "system" fn(*mut c_void) -> i32;
    type FnSymSetOptions    = unsafe extern "system" fn(u32) -> u32;
    type FnSymLoadModuleEx  = unsafe extern "system" fn(*mut c_void, *mut c_void, *const u8, *const u8, u64, u32, *mut c_void, u32) -> u64;
    type FnSymFromName      = unsafe extern "system" fn(*mut c_void, *const u8, *mut SymbolInfo) -> i32;
    type FnSymEnumSymbols   = unsafe extern "system" fn(*mut c_void, u64, *const u8, SymEnumSymbolsProc, usize) -> i32;
    type FnSymGetTypeInfo   = unsafe extern "system" fn(*mut c_void, u64, u32, u32, *mut c_void) -> i32;
    type FnSymSetSearchPath = unsafe extern "system" fn(*mut c_void, *const u8) -> i32;
    type SymEnumSymbolsProc = unsafe extern "system" fn(*mut SymbolInfo, u32, usize) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const u8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
        fn GetCurrentProcess() -> *mut c_void;
        fn LocalFree(ptr: *mut c_void) -> *mut c_void;
    }

    fn get_proc(module: *mut c_void, name: &[u8]) -> *const c_void {
        unsafe { GetProcAddress(module, name.as_ptr()) }
    }


    #[repr(C)]
    pub struct SymbolInfo {
        pub size_of_struct: u32,
        pub type_index:     u32,
        pub reserved:       [u64; 2],
        pub index:          u32,
        pub size:           u32,
        pub mod_base:       u64,
        pub flags:          u32,
        _pad:               u32,
        pub value:          u64,
        pub address:        u64,
        pub register:       u32,
        pub scope:          u32,
        pub tag:            u32,
        pub name_len:       u32,
        pub max_name_len:   u32,
        pub name:           [u8; 512],
    }

    impl Default for SymbolInfo {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    #[derive(Debug, Clone)]
    pub struct PdbSymbol {
        pub name: String,
        pub rva: u32,
        pub va: u64,
        pub kind: String,
        pub type_name: String,
        pub size: u64,
    }

    struct EnumContext {
        h_proc: *mut c_void,
        module_base: u64,
        sym_get_type_info: FnSymGetTypeInfo,
        out: *mut Vec<PdbSymbol>,
    }

    const TI_GET_SYMNAME: u32 = 1;
    const TI_GET_LENGTH: u32 = 2;
    const TI_GET_TYPEID: u32 = 4;
    const SYM_TAG_FUNCTION: u32 = 5;
    const SYM_TAG_DATA: u32 = 7;
    const SYM_TAG_PUBLIC: u32 = 10;


    pub fn load_pdb_symbol(
        dll_path: &str,
        func_name: &str,
        sym_path: &str,
        sym_server: &str,
        pdb_path: &str,
        image_base: u64,
        verbose: bool,
    ) -> Option<u32> {
        unsafe {
            let lib = LoadLibraryA(b"dbghelp.dll\0".as_ptr());
            if lib.is_null() { return None; }

            macro_rules! proc {
                ($name:literal, $ty:ty) => {{
                    let p = get_proc(lib, concat!($name, "\0").as_bytes());
                    if p.is_null() { return None; }
                    std::mem::transmute::<*const c_void, $ty>(p)
                }};
            }

            let sym_initialize:     FnSymInitialize    = proc!("SymInitialize",    FnSymInitialize);
            let sym_cleanup:        FnSymCleanup       = proc!("SymCleanup",       FnSymCleanup);
            let sym_set_options:    FnSymSetOptions    = proc!("SymSetOptions",    FnSymSetOptions);
            let sym_load_module_ex: FnSymLoadModuleEx  = proc!("SymLoadModuleEx",  FnSymLoadModuleEx);
            let sym_from_name:      FnSymFromName      = proc!("SymFromName",      FnSymFromName);
            let sym_set_search:     FnSymSetSearchPath = proc!("SymSetSearchPath", FnSymSetSearchPath);

            sym_set_options(0x00000002 | 0x00000004 | 0x00000010);

            let sp = build_search_path(dll_path, sym_path, sym_server, pdb_path);
            if verbose {
                eprintln!("  Symbol search path: {}", sp);
            }
            let sp_c = CString::new(sp.clone()).ok()?;

            let h_proc = GetCurrentProcess();
            let r = sym_initialize(h_proc, sp_c.as_ptr() as *const u8, 0);
            if r == 0 { return None; }
            struct Cleanup(*mut c_void, FnSymCleanup);
            impl Drop for Cleanup {
                fn drop(&mut self) { unsafe { (self.1)(self.0); } }
            }
            let _cleanup = Cleanup(h_proc, sym_cleanup);

            sym_set_search(h_proc, sp_c.as_ptr() as *const u8);

            let img_c = CString::new(dll_path).ok()?;
            let base = sym_load_module_ex(
                h_proc, std::ptr::null_mut(),
                img_c.as_ptr() as *const u8,
                std::ptr::null(),
                image_base, 0,
                std::ptr::null_mut(), 0,
            );
            if base == 0 {
                if verbose {
                    eprintln!("  SymLoadModuleEx failed for {}", dll_path);
                }
                return None;
            }

            let mut si = SymbolInfo::default();
            si.size_of_struct = 88;
            si.max_name_len = 512;

            let fn_c = CString::new(func_name).ok()?;
            let r = sym_from_name(h_proc, fn_c.as_ptr() as *const u8, &mut si);
            if r == 0 { return None; }

            if si.address < image_base { return None; }
            Some((si.address - image_base) as u32)
        }
    }

    pub fn load_pdb_symbols(
        dll_path: &str,
        sym_path: &str,
        sym_server: &str,
        pdb_path: &str,
        verbose: bool,
    ) -> Result<Vec<PdbSymbol>, String> {
        unsafe {
            let lib = LoadLibraryA(b"dbghelp.dll\0".as_ptr());
            if lib.is_null() {
                return Err("dbghelp.dll unavailable".to_owned());
            }

            macro_rules! proc {
                ($name:literal, $ty:ty) => {{
                    let p = get_proc(lib, concat!($name, "\0").as_bytes());
                    if p.is_null() { return Err(format!("missing dbghelp export {}", $name)); }
                    std::mem::transmute::<*const c_void, $ty>(p)
                }};
            }

            let sym_initialize:     FnSymInitialize    = proc!("SymInitialize", FnSymInitialize);
            let sym_cleanup:        FnSymCleanup       = proc!("SymCleanup", FnSymCleanup);
            let sym_set_options:    FnSymSetOptions    = proc!("SymSetOptions", FnSymSetOptions);
            let sym_load_module_ex: FnSymLoadModuleEx  = proc!("SymLoadModuleEx", FnSymLoadModuleEx);
            let sym_enum_symbols:   FnSymEnumSymbols   = proc!("SymEnumSymbols", FnSymEnumSymbols);
            let sym_get_type_info:  FnSymGetTypeInfo   = proc!("SymGetTypeInfo", FnSymGetTypeInfo);
            let sym_set_search:     FnSymSetSearchPath = proc!("SymSetSearchPath", FnSymSetSearchPath);

            sym_set_options(0x00000002 | 0x00000004 | 0x00000010);

            let sp = build_search_path(dll_path, sym_path, sym_server, pdb_path);
            if verbose {
                eprintln!("  Symbol search path: {}", sp);
            }
            let sp_c = CString::new(sp.clone()).map_err(|_| "invalid symbol path".to_owned())?;
            let h_proc = GetCurrentProcess();
            if sym_initialize(h_proc, sp_c.as_ptr() as *const u8, 0) == 0 {
                return Err("SymInitialize failed".to_owned());
            }
            struct Cleanup(*mut c_void, FnSymCleanup);
            impl Drop for Cleanup {
                fn drop(&mut self) { unsafe { (self.1)(self.0); } }
            }
            let _cleanup = Cleanup(h_proc, sym_cleanup);
            sym_set_search(h_proc, sp_c.as_ptr() as *const u8);

            let img_c = CString::new(dll_path).map_err(|_| "invalid module path".to_owned())?;
            let module_base = sym_load_module_ex(
                h_proc,
                std::ptr::null_mut(),
                img_c.as_ptr() as *const u8,
                std::ptr::null(),
                0,
                0,
                std::ptr::null_mut(),
                0,
            );
            if module_base == 0 {
                return Err(format!("SymLoadModuleEx failed for {}", dll_path));
            }

            let mask = CString::new("*").unwrap();
            let mut out: Vec<PdbSymbol> = Vec::new();
            let mut ctx = EnumContext {
                h_proc,
                module_base,
                sym_get_type_info,
                out: &mut out as *mut Vec<PdbSymbol>,
            };
            let ctx_ptr = &mut ctx as *mut EnumContext as usize;
            if sym_enum_symbols(h_proc, module_base, mask.as_ptr() as *const u8, enum_symbol_cb, ctx_ptr) == 0 {
                return Err("SymEnumSymbols failed".to_owned());
            }
            out.sort_by(|a, b| a.rva.cmp(&b.rva).then_with(|| a.name.cmp(&b.name)));
            out.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
            Ok(out)
        }
    }

    unsafe extern "system" fn enum_symbol_cb(sym_info: *mut SymbolInfo, _size: u32, user_ctx: usize) -> i32 {
        if sym_info.is_null() || user_ctx == 0 {
            return 1;
        }
        let info = &*sym_info;
        let ctx = &mut *(user_ctx as *mut EnumContext);
        let vec = &mut *ctx.out;
        let name_len = info.name_len as usize;
        let name = String::from_utf8_lossy(&info.name[..name_len.min(info.name.len())]).into_owned();
        if !name.is_empty() {
            let type_id = get_type_id(ctx.h_proc, ctx.module_base, info.type_index, ctx.sym_get_type_info);
            let type_name = type_id
                .and_then(|id| get_type_name(ctx.h_proc, ctx.module_base, id, ctx.sym_get_type_info))
                .unwrap_or_default();
            let size = type_id
                .and_then(|id| get_type_size(ctx.h_proc, ctx.module_base, id, ctx.sym_get_type_info))
                .unwrap_or(info.size as u64);
            let rva = info.address.saturating_sub(info.mod_base) as u32;
            vec.push(PdbSymbol {
                name,
                rva,
                va: info.address,
                kind: tag_name(info.tag).to_owned(),
                type_name,
                size,
            });
        }
        1
    }

    unsafe fn get_type_id(h_proc: *mut c_void, module_base: u64, type_index: u32, sym_get_type_info: FnSymGetTypeInfo) -> Option<u32> {
        if type_index == 0 {
            return None;
        }
        let mut type_id = 0u32;
        if sym_get_type_info(h_proc, module_base, type_index, TI_GET_TYPEID, &mut type_id as *mut _ as *mut c_void) == 0 {
            return Some(type_index);
        }
        Some(type_id)
    }

    unsafe fn get_type_size(h_proc: *mut c_void, module_base: u64, type_id: u32, sym_get_type_info: FnSymGetTypeInfo) -> Option<u64> {
        let mut len = 0u64;
        if sym_get_type_info(h_proc, module_base, type_id, TI_GET_LENGTH, &mut len as *mut _ as *mut c_void) == 0 {
            None
        } else {
            Some(len)
        }
    }

    unsafe fn get_type_name(h_proc: *mut c_void, module_base: u64, type_id: u32, sym_get_type_info: FnSymGetTypeInfo) -> Option<String> {
        let mut ptr: *mut u16 = std::ptr::null_mut();
        if sym_get_type_info(h_proc, module_base, type_id, TI_GET_SYMNAME, &mut ptr as *mut _ as *mut c_void) == 0 || ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(slice::from_raw_parts(ptr, len));
        LocalFree(ptr as *mut c_void);
        Some(s)
    }

    fn tag_name(tag: u32) -> &'static str {
        match tag {
            SYM_TAG_FUNCTION => "function",
            SYM_TAG_DATA => "data",
            SYM_TAG_PUBLIC => "public",
            _ => "symbol",
        }
    }

    fn build_search_path(dll_path: &str, sym_path: &str, sym_server: &str, pdb_path: &str) -> String {
        let mut local_entries = Vec::new();
        let mut server_entries = Vec::new();
        let mut seen = HashSet::new();

        let cache_dir = default_symbol_cache_dir();
        let default_server = if sym_server.is_empty() {
            DEFAULT_MS_SYMBOL_SERVER.to_owned()
        } else {
            sym_server.to_owned()
        };

        if !pdb_path.is_empty() {
            if let Some(dir) = Path::new(pdb_path).parent() {
                push_entry(&mut local_entries, &mut seen, dir.to_string_lossy().into_owned());
            }
        }

        if let Some(dir) = Path::new(dll_path).parent() {
            push_entry(&mut local_entries, &mut seen, dir.to_string_lossy().into_owned());
        }

        for raw in [sym_path, &std::env::var("_NT_SYMBOL_PATH").unwrap_or_default(), &std::env::var("_NT_ALT_SYMBOL_PATH").unwrap_or_default()] {
            for token in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                if is_server_entry(token) {
                    push_entry(&mut server_entries, &mut seen, token.to_owned());
                } else {
                    push_entry(&mut local_entries, &mut seen, token.to_owned());
                }
            }
        }

        if !cache_dir.is_empty() {
            let _ = std::fs::create_dir_all(&cache_dir);
            push_entry(&mut local_entries, &mut seen, cache_dir.clone());
        }

        if !default_server.is_empty() {
            let default_server_entry = format!("srv*{}*{}", cache_dir, default_server);
            if !server_entries.iter().any(|entry| entry.contains(&default_server)) {
                push_entry(&mut server_entries, &mut seen, default_server_entry);
            }
        }

        local_entries.extend(server_entries);
        local_entries.join(";")
    }

    fn default_symbol_cache_dir() -> String {
        if let Ok(path) = std::env::var("RESX_SYMBOL_CACHE") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }

        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let trimmed = local_app_data.trim();
            if !trimmed.is_empty() {
                return Path::new(trimmed).join("resx").join("symbols").to_string_lossy().into_owned();
            }
        }

        r"C:\Symbols".to_owned()
    }

    fn is_server_entry(entry: &str) -> bool {
        let lower = entry.to_ascii_lowercase();
        lower.contains("srv*") || lower.contains("symsrv") || lower.starts_with("http://") || lower.starts_with("https://")
    }

    fn push_entry(entries: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
        if seen.insert(value.to_ascii_lowercase()) {
            entries.push(value);
        }
    }
}

#[cfg(windows)]
pub use win::{load_pdb_symbol, load_pdb_symbols, PdbSymbol};

#[cfg(not(windows))]
pub fn load_pdb_symbol(
    _dll_path: &str, _func_name: &str, _sym_path: &str,
    _sym_server: &str, _pdb_path: &str, _image_base: u64, _verbose: bool,
) -> Option<u32> {
    None
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct PdbSymbol {
    pub name: String,
    pub rva: u32,
    pub va: u64,
    pub kind: String,
    pub type_name: String,
    pub size: u64,
}

#[cfg(not(windows))]
pub fn load_pdb_symbols(
    _dll_path: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _verbose: bool,
) -> Result<Vec<PdbSymbol>, String> {
    Err("PDB symbol enumeration is only supported on Windows".to_owned())
}
