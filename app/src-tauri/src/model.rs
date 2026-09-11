// Fetching the embedding model, verified.
//
// This lives apart from the Tauri command so it can be exercised without a
// window -- see src/bin/dlcheck.rs. A downloader whose only test is "someone
// clicked the button once on the machine that wrote it" is the piece of an
// install path most likely to be broken on somebody else's machine.
//
// THE HASH IS THE POINT. This is the one moment the program takes bytes from
// somewhere it does not control and then runs a model out of them. The bytes
// are checked against a constant compiled into the binary, and a mismatch is
// not a warning: nothing is installed and the partial file is removed.
use sha2::{Digest, Sha256};
use std::io::Write;

pub const MODEL_SHA256: &str =
    "797b70c4edf85907fe0a49eb85811256f65fa0f7bf52166b147fd16be2be4662";
pub const MODEL_BYTES: u64 = 45_949_216;
pub const MODEL_FILE: &str = "all-minilm-797b70c4.gguf";

/// Overridable so the download path can be exercised without publishing
/// anything. Production reads the pinned release asset.
pub fn url() -> String {
    std::env::var("UMBRA_MODEL_URL").unwrap_or_else(|_| {
        "https://github.com/AnshKanyadi/Umbra/releases/download/models-v1/all-minilm.gguf"
            .to_string()
    })
}

pub fn dir() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    Ok(std::path::PathBuf::from(home).join("Library/Application Support/Umbra/models"))
}

/// Downloads, verifies, and installs atomically. `progress` is called with
/// (bytes so far, total) as the body streams.
pub async fn fetch<F>(progress: F) -> Result<std::path::PathBuf, String>
where
    F: Fn(u64, u64),
{
    use futures_util::StreamExt;

    let dir = dir()?;
    let final_path = dir.join(MODEL_FILE);
    if final_path.exists() {
        return Ok(final_path);
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // A PARTIAL DOWNLOAD MUST NEVER LOOK LIKE A MODEL. It is written under a
    // temporary name and renamed only once the hash matches, so an interrupted
    // download leaves nothing that a later run would mistake for installed.
    let temp_path = dir.join(format!("{MODEL_FILE}.part"));
    let response = reqwest::get(url())
        .await
        .map_err(|e| format!("cannot reach the download: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("the download returned {}", response.status()));
    }
    let total = response.content_length().unwrap_or(MODEL_BYTES);

    let mut file = std::fs::File::create(&temp_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut seen: u64 = 0;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("the download stopped: {e}"))?;
        hasher.update(&chunk);
        file.write_all(&chunk).map_err(|e| e.to_string())?;
        seen += chunk.len() as u64;
        progress(seen, total);
    }
    file.flush().map_err(|e| e.to_string())?;
    drop(file);

    let got = format!("{:x}", hasher.finalize());
    if got != MODEL_SHA256 {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!(
            "the downloaded model does not match its pinned hash, so it was discarded. \
             Expected {MODEL_SHA256}, got {got}"
        ));
    }
    std::fs::rename(&temp_path, &final_path).map_err(|e| e.to_string())?;
    Ok(final_path)
}
