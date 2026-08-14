use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Result, anyhow};
use crate::api::socket::start_socket_server_with_shutdown;
use crate::manager::maps::reload_config;
use crate::monitoring::RingbufMonitor;
use tracing::{Level, info, warn};
use tracing_subscriber::EnvFilter;

mod api;
mod manager;
mod monitoring;
mod config;

const SOCKET_PATH: &str = "/tmp/ebpf-daemon.sock";

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_max_level(Level::INFO)
        .init();

    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }

    let prog_id = args
        .iter()
        .position(|a| a == "--prog-id")
        .and_then(|pos| args.get(pos + 1))
        .and_then(|s| s.parse::<i32>().ok());

    let mut config_path = "config2.yml".to_string();
    let mut config_arg_iter = args.iter().peekable();
    while let Some(arg) = config_arg_iter.next() {
        if arg == "--config" {
            if let Some(next) = config_arg_iter.next() {
                config_path = next.clone();
            } else {
                return Err(anyhow!("--config requires a path argument"));
            }
        }
    }

     // Load and apply initial configuration (non-fatal — daemon can run without config)
     if let Err(e) = reload_config(&config_path) {
         warn!("Failed to load initial config {}: {}", config_path, e);
         warn!("Starting without configuration. Use 'ebpf-ctl reload <config>' to load later.");
     }

    // Shared state for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Set up Ctrl-C handler
    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        r.store(false, Ordering::SeqCst);
    })
    .map_err(|e| anyhow!("Failed to set Ctrl-C handler: {}", e))?;

    // Clone for socket server thread (before monitoring thread moves it)
    let socket_running = running.clone();
    let main_running = running.clone();

    // Start monitoring in a separate thread
    let monitor_thread = thread::spawn(move || {
        if let Err(e) = run_monitoring(prog_id, running) {
            warn!("Monitoring error: {}", e);
        }
    });

    // Start Unix socket server in a separate thread
    let socket_thread = thread::spawn(move || {
        if let Err(e) = start_socket_server_with_shutdown(
            SOCKET_PATH,
            move || socket_running.load(Ordering::SeqCst),
        ) {
            warn!("Socket server error: {}", e);
        }
    });

    // Wait for Ctrl-C shutdown signal
    while main_running.load(Ordering::SeqCst) {
        thread::sleep(std::time::Duration::from_millis(100));
    }

    // Wait for threads to finish
    let _ = monitor_thread.join();
    let _ = socket_thread.join();

    // Clean up socket file
    let _ = std::fs::remove_file(SOCKET_PATH);

    info!("Daemon shut down");
    Ok(())
}

fn run_monitoring(prog_id: Option<i32>, running: Arc<AtomicBool>) -> Result<()> {
    let mut monitor = RingbufMonitor::new(prog_id)?;
    monitor.run_with_condition(|| running.load(Ordering::SeqCst))
}

fn print_usage() {
    eprintln!(
        r#"ebpf-daemon - eBPF XDP ringbuf consumer and management daemon

USAGE:
    ebpf-daemon [OPTIONS]

OPTIONS:
   --prog-id N         BPF program id (bpftool prog show | grep xdp)
    --config <path>     Path to configuration YAML file (default: config2.yml)
   -h, --help          Print this help message

DETECTION ORDER:
   1. Use explicit --prog-id if provided
   2. Try bpftool map show name events
   3. Scan XDP programs and inspect their map_ids

EXAMPLES:
   ebpf-daemon --prog-id 212              # Get events map from XDP program id
    ebpf-daemon --config /etc/ebpf/config2.yml
   ebpf-daemon                              # Auto-detect XDP program

FINDING MAP IDs:
   sudo bpftool prog show | grep xdp        # Find xdp program ids

The daemon runs two services:
1. Continuously monitors the eBPF XDP ringbuf and logs events
2. Listens for management commands on Unix socket at /tmp/ebpf-daemon.sock
"#
);
}