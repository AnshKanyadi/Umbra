// The desktop shell.
//
// It owns no logic. Indexing, search, keys and sync all live in the binaries
// this spawns, which are the same ones the command line uses and the same ones
// the tests cover. The rule that keeps it that way: nothing here parses prose.
// `umbra_ai --json` exists so this file reads fields rather than screen-scraping
// sentences that were written for a person to read.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Emitter;
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;

/// How many markdown files are under a folder, so the folder screen can say
/// what it found before anything is written.
#[tauri::command]
fn count_notes(folder: String) -> Result<usize, String> {
    fn walk(dir: &std::path::Path, n: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            // Dot-directories are skipped for the same reason the indexer skips
            // them: .obsidian and .trash are not notes.
            if name.starts_with('.') {
                continue;
            }
            if p.is_dir() {
                walk(&p, n);
            } else if p.extension().is_some_and(|x| x == "md") {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    walk(std::path::Path::new(&folder), &mut n);
    Ok(n)
}

mod model;

/// Downloads the model, verifies it, installs it. The work is in model.rs so
/// that the same code path is exercised by src/bin/dlcheck.rs without a window.
#[tauri::command]
async fn download_model(app: tauri::AppHandle) -> Result<String, String> {
    let handle = app.clone();
    let path = model::fetch(move |seen, total| {
        // Roughly every half megabyte, so the bar moves without the event
        // stream becoming the expensive part of the download.
        if seen % (512 * 1024) < 65536 || seen == total {
            let _ = handle.emit(
                "model-progress",
                serde_json::json!({ "bytes": seen, "of": total }),
            );
        }
    })
    .await?;
    Ok(path.to_string_lossy().to_string())
}

/// Where the embedding model is expected, and whether it is there.
///
/// Per ADR 0010 the weights are not in the repository and not in the app
/// bundle: they are downloaded once, verified against a pinned hash, and kept
/// beside the device key rather than in the vault. The downloader is not built
/// yet; this reports the path so the app can say what is missing instead of
/// failing inside a subprocess.
#[tauri::command]
fn model_status() -> Result<(String, bool), String> {
    let path = model::dir()?.join(model::MODEL_FILE);
    let there = path.exists();
    Ok((path.to_string_lossy().to_string(), there))
}

/// Index a vault, emitting progress as it goes.
///
/// The passphrase is passed in the environment rather than written to a file.
/// Neither is ideal -- an environment is readable by this user's other
/// processes -- but a file is a passphrase at rest, and the alternative the CLI
/// refuses outright is an argument vector, which is worse than both.
#[tauri::command]
async fn build_index(
    app: tauri::AppHandle,
    vault: String,
    index: String,
    model: String,
    passphrase: String,
) -> Result<String, String> {
    let (mut rx, _child) = app
        .shell()
        .sidecar("umbra_ai")
        .map_err(|e| e.to_string())?
        .env("UMBRA_PASSPHRASE", passphrase)
        .args([
            "--vault", &vault, "--index", &index, "--model", &model, "--json",
            "--build",
        ])
        .spawn()
        .map_err(|e| e.to_string())?;

    let mut last = String::new();
    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stdout(line) => {
                let line = String::from_utf8_lossy(&line).trim().to_string();
                if line.is_empty() {
                    continue;
                }
                // Forwarded verbatim. The shell does not interpret; the screen
                // decides what a progress event means.
                let _ = app.emit("index-progress", line.clone());
                last = line;
            }
            CommandEvent::Terminated(payload) => {
                if payload.code != Some(0) {
                    return Err(format!("indexing failed with code {:?}", payload.code));
                }
            }
            _ => {}
        }
    }
    Ok(last)
}

/// One search. Returns the JSON object verbatim for the page to render.
#[tauri::command]
async fn ask(
    app: tauri::AppHandle,
    vault: String,
    index: String,
    model: String,
    passphrase: String,
    question: String,
    floor: String,
) -> Result<String, String> {
    let output = app
        .shell()
        .sidecar("umbra_ai")
        .map_err(|e| e.to_string())?
        .env("UMBRA_PASSPHRASE", passphrase)
        .args([
            "--vault", &vault, "--index", &index, "--model", &model, "--floor",
            &floor, "--json", "--ask", &question,
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Create the vault. Separate from indexing because it is the one step that
/// mints keys, and because it is the only command allowed to.
#[tauri::command]
async fn create_vault(
    app: tauri::AppHandle,
    vault: String,
    passphrase: String,
) -> Result<String, String> {
    let output = app
        .shell()
        .sidecar("umbra_sync")
        .map_err(|e| e.to_string())?
        .env("UMBRA_PASSPHRASE", passphrase)
        .args(["--dir", &vault, "--create"])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(text)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            count_notes,
            model_status,
            download_model,
            build_index,
            ask,
            create_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
