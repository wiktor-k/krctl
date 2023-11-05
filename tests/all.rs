use rstest::{fixture, rstest};
use std::path::PathBuf;
use testresult::TestResult;

//use tempdir::TempDir;

#[fixture]
fn temp_output_dir() -> PathBuf {
    //let output = TempDir::new("krctl")?;
    let output = std::env::temp_dir().join(format!(
        "krapi-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    std::fs::create_dir(output.clone()).expect("tempdir creation succeed");
    //let output = output.as_path();
    output
}

#[rstest]
fn main(
    #[files("test-cases/*")] path: PathBuf,
    #[from(temp_output_dir)] output: PathBuf,
) -> TestResult {
    eprintln!("Using temp dir for tests: {}", output.display());
    for key in path.join("input/import").read_dir()? {
        krctl::import(krctl::ImportCommand {
            key: key?.path(),
            output: output.clone(),
        })?;
    }
    assert!(!dir_diff::is_different(output, path.join("output"))
        .expect("directories to have the same contents"));
    Ok(())
}
