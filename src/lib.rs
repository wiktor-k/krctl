use clap::Parser;
use sequoia_openpgp::{cert::CertParser, parse::Parse, Cert};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub enum Command {
    Import(ImportCommand),
}

#[derive(Parser, Debug)]
pub struct ImportCommand {
    pub key: PathBuf,
    pub output: PathBuf,
}

pub fn import(command: ImportCommand) -> std::io::Result<()> {
    let user_dir = command.output.join(command.key.file_stem().unwrap());
    eprintln!("this is upser dir: {:?}", user_dir);
    for cert in CertParser::from_file(command.key).unwrap() {
        if let Ok(cert) = cert {
            let cert_dir = user_dir.join(cert.fingerprint().to_hex());
            let subkeys_dir = cert_dir.join("subkey");
            std::fs::create_dir_all(&subkeys_dir)?;
            for subkey in cert.keys().subkeys() {
                let subkey_dir = subkeys_dir.join(subkey.fingerprint().to_hex());
                std::fs::create_dir_all(&subkey_dir)?;
            }
            eprintln!("cert fpr dir: {:}", cert_dir.display());
        } else {
            eprintln!("err");
        }
    }
    Ok(())
}
