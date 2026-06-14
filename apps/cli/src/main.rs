use packet_engine::capture::PacketCapture;
use threat_engine::ThreatDetector;
use tracing::{info, error};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("netsentinel=info,warn")
        .init();

    println!("╔════════════════════════════════════════╗");
    println!("║        NetSentinel - CLI Mode          ║");
    println!("║     Rust Network Security Monitor       ║");
    println!("╚════════════════════════════════════════╝");
    println!();

    let interfaces = PacketCapture::list_interfaces()?;
    if interfaces.is_empty() {
        eprintln!("No network interfaces found. Install Npcap from https://npcap.com");
        return Ok(());
    }

    println!("Available network interfaces:");
    for (i, name) in interfaces.iter().enumerate() {
        println!("  [{i}] {name}");
    }
    print!("\nSelect interface [0]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let idx: usize = input.trim().parse().unwrap_or(0);
    let interface = interfaces.get(idx).unwrap_or(&interfaces[0]).clone();
    println!("\nSelected: {interface}");

    let (detector, _alert_rx) = ThreatDetector::new();
    let detector = std::sync::Arc::new(detector);

    info!("Starting capture on {interface}...");
    println!("\nCapturing packets. Press Ctrl+C to stop.\n");

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

    let iface_clone = interface.clone();
    let capture_handle = tokio::spawn(async move {
        let mut capture = match PacketCapture::new(&iface_clone) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to open interface: {e}");
                return;
            }
        };
        if let Err(e) = capture.start(event_tx).await {
            error!("Capture error: {e}");
        }
    });

    let det = detector.clone();
    let analyze_handle = tokio::spawn(async move {
        let mut event_count = 0u64;
        let mut alert_count = 0u64;

        while let Some(event) = event_rx.recv().await {
            event_count += 1;
            let alerts = det.analyze(&event);
            for alert in &alerts {
                alert_count += 1;
                println!();
                println!("━━━ ALERT #{alert_count} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("  Severity:  {}", alert.severity);
                println!("  Title:     {}", alert.title);
                println!("  Detail:    {}", alert.description);
                if let Some(ip) = alert.source_ip {
                    println!("  Source:    {ip}");
                }
                if let Some(ip) = alert.destination_ip {
                    println!("  Dest:      {ip}");
                }
                if let Some(port) = alert.port {
                    println!("  Port:      {port}");
                }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            }

            if event_count.is_multiple_of(100) {
                let candidates = det.get_port_scan_candidates();
                print!("\r  Events: {event_count} | Alerts: {alert_count} | Port scans tracked: {}", candidates.len());
                io::stdout().flush().ok();
            }
        }
    });

    tokio::select! {
        _ = capture_handle => {}
        _ = analyze_handle => {}
    }

    Ok(())
}
