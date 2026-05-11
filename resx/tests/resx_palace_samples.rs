#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const EXPORTS: &[&str] = &[
    "ResxParsePacket",
    "ResxDeviceIoctlDispatch",
    "ResxThreadCallbackEntry",
    "ResxSwitchJumpTableDispatch",
    "ResxIndirectCallMessage",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("resx crate should be inside workspace")
        .to_path_buf()
}

fn corpus_root() -> PathBuf {
    workspace_root().join("resx-palace")
}

fn build_dir() -> PathBuf {
    corpus_root().join("build")
}

fn sample_path(name: &str) -> PathBuf {
    build_dir().join(name)
}

fn ensure_samples() -> Option<(PathBuf, PathBuf)> {
    let dll = sample_path("resx_palace.dll");
    let exe = sample_path("resx_palace_probe.exe");
    if dll.exists() && exe.exists() {
        return Some((dll, exe));
    }

    let script = corpus_root().join("scripts").join("build.ps1");
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script.to_str().unwrap(),
        ])
        .current_dir(workspace_root())
        .output()
        .expect("failed to launch resx-palace build script");

    if !output.status.success() {
        eprintln!(
            "skipping resx-palace integration test: sample build failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    if dll.exists() && exe.exists() {
        Some((dll, exe))
    } else {
        eprintln!("skipping resx-palace integration test: build did not produce expected samples");
        None
    }
}

fn run_resx(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(args)
        .output()
        .expect("failed to run resx");
    assert!(
        output.status.success(),
        "resx failed for {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("resx stdout was not utf-8")
}

fn run_json(args: &[&str]) -> Value {
    serde_json::from_str(&run_resx(args)).expect("resx stdout was not json")
}

fn array_contains_name(items: &Value, name: &str) -> bool {
    items
        .as_array()
        .is_some_and(|values| values.iter().any(|item| item["name"] == name))
}

#[test]
fn resx_palace_samples_exercise_binary_analysis_commands() {
    let Some((dll, exe)) = ensure_samples() else {
        return;
    };
    let dll = dll.to_str().unwrap();
    let exe = exe.to_str().unwrap();
    let scan_root = build_dir();
    let scan_root = scan_root.to_str().unwrap();

    let peinfo = run_json(&["peinfo", dll, "--json", "--no-color", "--quiet"]);
    assert_eq!(peinfo["schema_version"], 1);
    assert_eq!(peinfo["peinfo"]["file_name"], "resx_palace.dll");
    assert!(peinfo["peinfo"]["sections"]
        .as_array()
        .is_some_and(|sections| !sections.is_empty()));

    let eat = run_json(&["eat", dll, "--json", "--no-color", "--quiet"]);
    assert_eq!(eat["schema_version"], 1);
    for expected in EXPORTS {
        assert!(
            array_contains_name(&eat["exports"], expected),
            "missing export {expected} in {eat:#}"
        );
    }

    for expected in EXPORTS {
        let dump = run_json(&["dump", dll, expected, "--json", "--no-color", "--quiet"]);
        assert_eq!(dump["schema_version"], 1);
        assert_eq!(dump["dump"]["function"], *expected);
        assert!(dump["dump"]["instructions"]
            .as_array()
            .is_some_and(|instructions| !instructions.is_empty()));
    }

    let cfg = run_resx(&[
        "cfg",
        dll,
        "ResxSwitchJumpTableDispatch",
        "--no-color",
        "--quiet",
    ]);
    assert!(cfg.contains("CFG: resx_palace.dll!ResxSwitchJumpTableDispatch"));
    assert!(
        cfg.contains("block") || cfg.contains("Basic") || cfg.contains("->"),
        "cfg output did not look like a graph:\n{cfg}"
    );

    let reconstruct = run_json(&[
        "reconstruct-cfg",
        exe,
        "--json",
        "--no-color",
        "--quiet",
        "--no-pdb",
        "--depth",
        "2",
        "--max-total",
        "64",
    ]);
    assert_eq!(reconstruct["schema_version"], 1);
    assert_eq!(
        reconstruct["reconstruct_cfg"]["image"],
        "resx_palace_probe.exe"
    );
    assert!(reconstruct["reconstruct_cfg"]["roots"]
        .as_array()
        .is_some_and(|roots| !roots.is_empty()));

    let scan = run_json(&[
        "scan",
        scan_root,
        "--extensions",
        "exe,dll",
        "--max-files",
        "8",
        "--max-candidates",
        "16",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(scan["schema_version"], 1);
    assert_eq!(scan["kind"], "scan");
    let results = scan["results"]
        .as_array()
        .expect("scan results should be an array");
    assert!(results.iter().any(|item| item["name"] == "resx_palace.dll"));
    assert!(results
        .iter()
        .any(|item| item["name"] == "resx_palace_probe.exe"));

    let dll_report = results
        .iter()
        .find(|item| item["name"] == "resx_palace.dll")
        .expect("missing DLL scan report");
    for expected in [
        "ResxParsePacket",
        "ResxDeviceIoctlDispatch",
        "ResxThreadCallbackEntry",
        "ResxSwitchJumpTableDispatch",
        "ResxIndirectCallMessage",
    ] {
        assert!(
            array_contains_name(&dll_report["candidates"], expected),
            "missing scan candidate {expected} in {dll_report:#}"
        );
    }
}
