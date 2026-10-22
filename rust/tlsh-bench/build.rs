//! Links the benchmark crate statically against libhasher.
//!
//! libhasher.a is taken from `../../src/lib/.libs` (the autotools build tree
//! two levels up) unless `HASHER_LIB_DIR` points somewhere else. The system
//! libraries libhasher itself needs (libcrypto, libfuzzy, the C++ runtime)
//! are picked up from the configured top-level Makefile when it is present,
//! and otherwise from pkg-config / a few well-known prefixes.
//!
//! Everything is passed as ordered linker arguments: the archive by absolute
//! path (so an installed libhasher.dylib on LIBRARY_PATH cannot shadow it),
//! followed by the libraries it depends on (so GNU ld's --as-needed keeps
//! them).

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const FUZZY_PREFIXES: &[&str] = &["/opt/local/lib", "/opt/homebrew/lib", "/usr/local/lib", "/usr/lib"];

#[derive(Default)]
struct Link {
    search: Vec<String>,
    libs: Vec<String>,
    seen_search: HashSet<String>,
    seen_libs: HashSet<String>,
}

impl Link {
    fn search(&mut self, dir: &str) {
        if self.seen_search.insert(dir.to_string()) {
            self.search.push(dir.to_string());
        }
    }

    fn lib(&mut self, name: &str) {
        if self.seen_libs.insert(name.to_string()) {
            self.libs.push(name.to_string());
        }
    }

    fn has_lib(&self, name: &str) -> bool {
        self.seen_libs.contains(name)
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=HASHER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=HASHER_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=FUZZY_LIB_DIR");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("..").join("..");

    let lib_dir = env::var_os("HASHER_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("src").join("lib").join(".libs"));

    let archive = lib_dir.join("libhasher.a");
    println!("cargo:rerun-if-changed={}", archive.display());
    let archive = archive.canonicalize().unwrap_or_else(|_| {
        panic!(
            "{} not found; build libhasher first (./configure && make in the repo root) \
             or set HASHER_LIB_DIR to the directory holding libhasher.a",
            archive.display()
        )
    });

    let mut link = Link::default();

    // The build tree's Makefile records the -L/-l flags configure chose.
    let build_dir = env::var_os("HASHER_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.clone());
    link_from_makefile(&build_dir.join("Makefile"), &mut link);

    if !link.has_lib("crypto") {
        link_crypto(&mut link);
    }
    if !link.has_lib("fuzzy") {
        link.lib("fuzzy");
    }
    fuzzy_search_dir(&mut link);

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    link.lib(if os == "macos" || os == "ios" { "c++" } else { "stdc++" });

    for dir in &link.search {
        println!("cargo:rustc-link-arg=-L{dir}");
    }
    println!("cargo:rustc-link-arg={}", archive.display());
    for lib in &link.libs {
        println!("cargo:rustc-link-arg=-l{lib}");
    }
}

/// Collects the -L and -l flags from the variables configure fills in.
fn link_from_makefile(makefile: &Path, link: &mut Link) {
    let Ok(text) = fs::read_to_string(makefile) else {
        return;
    };
    println!("cargo:rerun-if-changed={}", makefile.display());

    for line in text.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if !matches!(
            name.trim(),
            "PROJECT_LIBS" | "PROJECT_LDFLAGS" | "FUZZY_LDFLAGS" | "FUZZY_LIBS" | "LIBS"
        ) {
            continue;
        }
        for tok in value.split_whitespace() {
            if let Some(dir) = tok.strip_prefix("-L") {
                link.search(dir);
            } else if let Some(lib) = tok.strip_prefix("-l") {
                link.lib(lib);
            }
        }
    }
}

fn link_crypto(link: &mut Link) {
    match pkg_config::Config::new().cargo_metadata(false).probe("libcrypto") {
        Ok(lib) => {
            for p in &lib.link_paths {
                link.search(&p.display().to_string());
            }
            for l in &lib.libs {
                link.lib(l);
            }
        }
        Err(_) => link.lib("crypto"),
    }
}

/// libfuzzy (ssdeep) usually has no pkg-config file and configure records no
/// -L for it; add the directory it lives in if it is not on the default path.
fn fuzzy_search_dir(link: &mut Link) {
    if let Some(dir) = env::var_os("FUZZY_LIB_DIR") {
        link.search(&PathBuf::from(dir).display().to_string());
        return;
    }
    for prefix in FUZZY_PREFIXES {
        let p = Path::new(prefix);
        if ["libfuzzy.dylib", "libfuzzy.so", "libfuzzy.a"]
            .iter()
            .any(|f| p.join(f).exists())
        {
            link.search(prefix);
            return;
        }
    }
}
