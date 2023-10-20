use clap::Parser;
use krctl::Command;

fn main() -> std::io::Result<()> {
    let command = Command::parse();
    println!("Hello, world: {:?}", command);
    match command {
        Command::Import(import) => krctl::import(import)?,
    }
    Ok(())
}
