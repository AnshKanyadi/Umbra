// The download path, exercised without a window.
//
// It calls the same function the app calls, so this cannot pass while the app
// is broken. Point UMBRA_MODEL_URL at a local file server and run it twice: once
// against good bytes, once against corrupted ones.
#[path = "../model.rs"]
mod model;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Cell rather than a plain mut, because fetch takes an Fn: the callback is
    // invoked many times and must not require unique access.
    let last = std::cell::Cell::new(0u64);
    match model::fetch(|seen, total| {
        if seen - last.get() > 8 * 1024 * 1024 {
            last.set(seen);
            eprintln!("  {} / {} bytes", seen, total);
        }
    })
    .await
    {
        Ok(p) => {
            println!("INSTALLED {}", p.display());
            println!("exists: {}", p.exists());
        }
        Err(e) => println!("REFUSED {e}"),
    }
    let part = model::dir().unwrap().join(format!("{}.part", model::MODEL_FILE));
    println!("partial file left behind: {}", part.exists());
}
