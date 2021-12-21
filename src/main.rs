use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process;

use lddtree::DependencyAnalyzer;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    if let Some(pathname) = args.next() {
        let root = args
            .next()
            .map(|s| PathBuf::from(&s))
            .unwrap_or_else(|| PathBuf::from("/"));
        let analyzer = DependencyAnalyzer::new(root);
        let deps = analyzer.analyze(pathname)?;
        println!("{:#?}", deps);
    } else {
        eprintln!("USAGE: lddtree <pathname> [root]");
        process::exit(1);
    }
    Ok(())
}
