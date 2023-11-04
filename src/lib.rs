use clap::Parser;
use sequoia_openpgp::{
    armor::{Kind, Writer},
    cert::{amalgamation::ValidAmalgamation, CertParser},
    parse::Parse,
    policy::{self, StandardPolicy},
    serialize::Serialize,
    Packet,
};
use std::{fs::File, path::PathBuf};

#[derive(Parser, Debug)]
pub enum Command {
    Import(ImportCommand),
}

#[derive(Parser, Debug)]
pub struct ImportCommand {
    pub key: PathBuf,
    pub output: PathBuf,
}

use regex::Regex;

pub fn import(command: ImportCommand) -> std::io::Result<()> {
    let policy = StandardPolicy::new();
    let uid_re = Regex::new(r"[^A-Za-z0-9.]").unwrap();
    let user_dir = command.output.join(command.key.file_stem().unwrap());
    eprintln!("this is upser dir: {:?}", user_dir);
    for cert in CertParser::from_file(command.key).unwrap() {
        if let Ok(cert) = cert {
            let cert = cert.with_policy(&policy, None).unwrap();
            let cert_dir = user_dir.join(cert.fingerprint().to_hex());
            let subkeys_dir = cert_dir.join("subkey");
            std::fs::create_dir_all(&subkeys_dir)?;
            for subkey in cert.keys().subkeys() {
                let subkey_dir = subkeys_dir.join(subkey.fingerprint().to_hex());
                std::fs::create_dir_all(&subkey_dir)?;

                let mut subkey_packet_file = subkey_dir.join(subkey.fingerprint().to_hex());
                subkey_packet_file.set_extension("asc");
                let mut bytes = Writer::new(File::create(subkey_packet_file)?, Kind::File)?;
                Packet::from(subkey.key().clone())
                    .serialize(&mut bytes)
                    .unwrap();
                bytes.finalize()?;

                let certification_dir = subkey_dir.join("certification");
                std::fs::create_dir_all(&certification_dir)?;

                let mut binding_file = certification_dir.join(subkey.fingerprint().to_hex());
                binding_file.set_extension("asc");

                let mut bytes = Writer::new(File::create(binding_file)?, Kind::File)?;
                Packet::from(subkey.binding_signature().clone())
                    .serialize(&mut bytes)
                    .unwrap();
                bytes.finalize()?;

                /*                for certification in subkey.certifications() {
                                  let mut certification_file = certification_dir
                                      .join(certification.issuer_fingerprints().next().unwrap().to_hex());
                                  certification_file.set_extension("asc");

                                  let mut bytes = Writer::new(File::create(certification_file)?, Kind::File)?;
                                  Packet::from(certification.clone())
                                      .serialize(&mut bytes)
                                      .unwrap();
                                  bytes.finalize()?;
                              }
                */
            }
            let uids_dir = cert_dir.join("uid");
            std::fs::create_dir_all(&uids_dir)?;
            for uid in cert.userids() {
                let simplified_uid = format!(
                    "{}{}",
                    uid_re.replace_all(&uid.userid().to_string(), "_"),
                    &sha256::digest(uid.userid().to_string())[0..8]
                );
                let uid_dir = uids_dir.join(&simplified_uid);
                std::fs::create_dir_all(&uid_dir)?;
                let uid_file = uid_dir.join(&format!("{}.asc", &simplified_uid));

                let mut bytes = Writer::new(File::create(uid_file)?, Kind::File)?;
                Packet::from(uid.component().clone())
                    .serialize(&mut bytes)
                    .unwrap();
                bytes.finalize()?;
            }
            eprintln!("cert fpr dir: {:}", cert_dir.display());
        } else {
            eprintln!("err");
        }
    }
    Ok(())
}
