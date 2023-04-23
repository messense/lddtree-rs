use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process;

use lddtree::{DependencyAnalyzer, Library};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    if let Some(pathname) = args.next() {
        let root = args
            .next()
            .map(|s| PathBuf::from(&s))
            .unwrap_or_else(|| PathBuf::from("/"));
        let lib_paths = args.map(|s| PathBuf::from(&s)).collect();
        let analyzer = DependencyAnalyzer::new(root).library_paths(lib_paths);
        let deps = analyzer.analyze(pathname)?;
        if let Some(interp) = deps.interpreter {
            if let Some(path) = deps
                .libraries
                .get(&interp)
                .and_then(|lib| lib.realpath.as_ref())
            {
                println!("{} => {}", interp, path.display());
            } else {
                println!("{} => not found", interp);
            }
        }
        for needed in deps.needed {
            print_library(&needed, &deps.libraries, 0, HashSet::new());
        }
    } else {
        eprintln!("USAGE: lddtree <pathname> [root] [library path...]");
        process::exit(1);
    }
    Ok(())
}

fn print_library(
    name: &str,
    libraries: &HashMap<String, Library>,
    level: usize,
    mut history: HashSet<PathBuf>,
) {
    let padding = " ".repeat(level);
    if let Some(lib) = libraries.get(name) {
        if let Some(path) = lib.realpath.as_ref() {
            let looping = !history.insert(path.to_path_buf());
            let loop_annotation = if looping { " (DEPENDENCY CYCLE)" } else { "" };
            println!(
                "{}{} => {}{}",
                padding,
                name,
                path.display(),
                loop_annotation
            );
            if looping {
                return;
            };
        } else {
            println!("{}{} => not found", padding, name);
        }

        for needed in &lib.needed {
            print_library(needed, libraries, level + 4, history.clone());
        }
    }
}
