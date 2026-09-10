// A window and nothing else.
//
// This exists so that signing, notarization and Gatekeeper are exercised in
// week one rather than at the end. It is the step with the least to show for
// itself and the most capacity to eat days, so it is done first and on
// something that cannot itself be broken.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
