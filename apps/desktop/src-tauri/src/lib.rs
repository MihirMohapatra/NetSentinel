mod commands;
mod state;

use state::AppState;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("netsentinel=info")
        .init();

    let app_state = AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_alerts,
            commands::get_connections,
            commands::get_dns_history,
            commands::get_port_scan_candidates,
            commands::start_capture,
            commands::stop_capture,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetSentinel");
}