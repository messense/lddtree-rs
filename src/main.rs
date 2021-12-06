use std::env;
use std::error::Error;
use std::process;

use lddtree::DependencyAnalyzer;

fn main() -> Result<(), Box<dyn Error>> {
    if let Some(pathname) = env::args().skip(1).next() {
        let analyzer = DependencyAnalyzer::new();
        let deps = analyzer.analyze(pathname)?;
        println!("{:#?}", deps);
    } else {
        eprintln!("USAGE: lddtree <pathname>");
        process::exit(1);
    }
    Ok(())
}
