//! Sync the WIT files from the pinned `boogy-wit` crate into `./wit` so
//! `wit_bindgen::generate!` (which needs a manifest-relative literal path)
//! always sees definitions matching the SDK revision in Cargo.lock. `wit/` is
//! generated — it is gitignored, never edited by hand.

use std::fs;
use std::path::Path;

fn main() {
    let src = boogy_wit::wit_dir();
    let dst = Path::new(env!("CARGO_MANIFEST_DIR")).join("wit");
    fs::create_dir_all(&dst).expect("create wit/ dir");
    for entry in fs::read_dir(&src).expect("read boogy-wit wit dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "wit") {
            let name = path.file_name().expect("wit file name");
            fs::copy(&path, dst.join(name)).expect("copy wit file");
        }
    }
    println!("cargo:rerun-if-changed={}", src.display());
}
