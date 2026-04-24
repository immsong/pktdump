use anyhow::{Context, Result};
use chrono::{Duration, Local};
use clap::Parser;
use pcap::{Capture, Device};
use rusqlite::{Connection, params};
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TrySendError};
use std::thread;

/// Top-level TOML configuration.
#[derive(Debug, Deserialize, Clone)]
struct AppConfig {
    usb_mount_path: String,
    retention_days: i64,
    network: NetworkConfig,
}

/// Network capture filter configuration.
#[derive(Debug, Deserialize, Clone)]
struct NetworkConfig {
    interface: String,
    ips: Vec<String>,
    ports: Vec<u16>,
    use_multicast: bool,
    multicast_groups: Vec<String>,
}

/// Command-line arguments. Defaults to config.toml.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

/// Minimal packet data passed from the capture loop to the DB writer thread.
struct PacketData {
    ts_total_usec: i64,
    payload: Vec<u8>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load and parse the configuration file.
    let settings = config::Config::builder()
        .add_source(config::File::with_name(&args.config))
        .build()
        .context("failed to load config file")?;

    let config: AppConfig = settings
        .try_deserialize()
        .context("failed to parse configuration")?;

    validate_config(&config)?;

    println!("[System] starting packet capture: {:?}", config);

    // Separate packet capture from SQLite writes.
    // A bounded queue prevents unbounded memory growth if DB writes fall behind.
    const DB_QUEUE_CAPACITY: usize = 10_000;
    let (tx, rx) = mpsc::sync_channel::<PacketData>(DB_QUEUE_CAPACITY);
    let db_config = config.clone();

    // Dedicated DB writer thread.
    // It switches to a new DB file when the local date changes.
    let db_handle = thread::spawn(move || -> Result<()> {
        let mut current_date = Local::now().format("%Y%m%d").to_string();
        let mut conn = setup_db(&db_config.usb_mount_path, &current_date)
            .context("failed to initialize database")?;

        while let Ok(packet) = rx.recv() {
            let now_date = Local::now().format("%Y%m%d").to_string();

            // Rotate DB file once the date changes.
            if now_date != current_date {
                println!("[DB] date changed: {} -> {}", current_date, now_date);

                // Close the old connection before opening the next DB file.
                // This makes WAL/SHM file handling more predictable.
                drop(conn);

                conn = setup_db(&db_config.usb_mount_path, &now_date)
                    .context("failed to rotate database")?;
                current_date = now_date;

                if let Err(err) =
                    cleanup_old_files(&db_config.usb_mount_path, db_config.retention_days)
                {
                    eprintln!("[Cleanup][WARN] failed to clean old files: {err:#}");
                }
            }

            // Do not silently ignore INSERT failures.
            if let Err(err) = conn.execute(
                "INSERT INTO packets (ts_usec, payload) VALUES (?, ?)",
                params![packet.ts_total_usec, packet.payload],
            ) {
                eprintln!("[DB][ERROR] failed to insert packet: {err:#}");
            }
        }

        Ok(())
    });

    // Find and open the configured network interface.
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name == config.network.interface)
        .ok_or_else(|| anyhow::anyhow!("interface '{}' not found", config.network.interface))?;

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()?;

    // Build the BPF filter from configuration values.
    let mut filter_parts = Vec::new();

    // BPF "port" matches both TCP and UDP ports.
    if !config.network.ports.is_empty() {
        let p_str = config
            .network
            .ports
            .iter()
            .map(|p| format!("port {}", p))
            .collect::<Vec<_>>()
            .join(" or ");

        filter_parts.push(format!("({})", p_str));
    }

    // Match packets where either source or destination IP is in the configured list.
    if !config.network.ips.is_empty() {
        let ip_str = config
            .network
            .ips
            .iter()
            .map(|ip| format!("host {}", ip))
            .collect::<Vec<_>>()
            .join(" or ");

        filter_parts.push(format!("({})", ip_str));
    }

    // Add multicast destination filters only when multicast mode is enabled.
    if config.network.use_multicast && !config.network.multicast_groups.is_empty() {
        let m_str = config
            .network
            .multicast_groups
            .iter()
            .map(|g| format!("dst host {}", g))
            .collect::<Vec<_>>()
            .join(" or ");

        filter_parts.push(format!("({})", m_str));
    }

    // Always capture IP packets, then add optional AND conditions.
    let final_filter = if filter_parts.is_empty() {
        "ip".to_string()
    } else {
        format!("ip and {}", filter_parts.join(" and "))
    };

    cap.filter(&final_filter, true)?;
    println!("[Net] applied capture filter: \"{}\"", final_filter);

    // Capture packets and pass only timestamp + payload to the DB writer.
    let capture_result: Result<()> = loop {
        let packet = match cap.next_packet() {
            Ok(packet) => packet,
            // Timeouts may be normal depending on the capture backend.
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => break Err(anyhow::anyhow!("packet capture failed: {err:#}")),
        };

        let total_usec =
            (packet.header.ts.tv_sec as i64 * 1_000_000) + packet.header.ts.tv_usec as i64;

        // Drop the packet if the DB queue is full.
        // Use blocking send() instead if lossless persistence is more important.
        match tx.try_send(PacketData {
            ts_total_usec: total_usec,
            payload: packet.data.to_vec(),
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                eprintln!("[DB][WARN] DB queue is full; dropped one packet");
            }
            Err(TrySendError::Disconnected(_)) => {
                break Err(anyhow::anyhow!("DB writer thread has stopped"));
            }
        }
    };

    // Close the sender and check whether the DB writer exited cleanly.
    drop(tx);

    db_handle
        .join()
        .map_err(|_| anyhow::anyhow!("DB writer thread panicked"))??;

    capture_result
}

/// Validate values before they are used in BPF filters or filesystem paths.
fn validate_config(config: &AppConfig) -> Result<()> {
    if config.usb_mount_path.trim().is_empty() {
        return Err(anyhow::anyhow!("usb_mount_path must not be empty"));
    }

    if config.network.interface.trim().is_empty() {
        return Err(anyhow::anyhow!("network.interface must not be empty"));
    }

    if config.retention_days < 0 {
        return Err(anyhow::anyhow!("retention_days must be zero or greater"));
    }

    for ip in &config.network.ips {
        ip.parse::<IpAddr>()
            .with_context(|| format!("invalid ips value: {ip}"))?;
    }

    for group in &config.network.multicast_groups {
        let addr = group
            .parse::<IpAddr>()
            .with_context(|| format!("invalid multicast_groups value: {group}"))?;

        if config.network.use_multicast && !addr.is_multicast() {
            return Err(anyhow::anyhow!(
                "multicast_groups must contain only multicast addresses when multicast is enabled: {group}"
            ));
        }
    }

    Ok(())
}

/// Open the SQLite DB for the given date and create the schema if needed.
fn setup_db(base_path: &str, date_str: &str) -> Result<Connection> {
    let path = PathBuf::from(base_path);

    if !path.exists() {
        fs::create_dir_all(&path)?;
    }

    let db_path = path.join(format!("pktdump_{}.db", date_str));
    let conn = Connection::open(db_path)?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY,
            ts_usec INTEGER,
            payload BLOB
         );",
    )?;

    Ok(conn)
}

/// Delete old daily DB files and their SQLite WAL/SHM sidecar files.
fn cleanup_old_files(base_path: &str, days: i64) -> Result<()> {
    let limit_str = (Local::now() - Duration::days(days))
        .format("%Y%m%d")
        .to_string();

    for entry in fs::read_dir(base_path).context("failed to read DB directory")? {
        let entry = entry?;
        let name = entry.file_name().into_string().unwrap_or_default();

        // Only delete files matching pktdump_YYYYMMDD.db.
        if !is_packet_db_name(&name) {
            continue;
        }

        let date_part = &name[8..16];

        // Lexicographic comparison is safe for YYYYMMDD.
        if date_part < limit_str.as_str() {
            let path = entry.path();

            println!("[Cleanup] deleting old DB file: {}", path.display());

            remove_file_if_exists(&path)?;
            remove_file_if_exists(&path.with_extension("db-wal"))?;
            remove_file_if_exists(&path.with_extension("db-shm"))?;
        }
    }

    Ok(())
}

/// Return true only for filenames like pktdump_YYYYMMDD.db.
fn is_packet_db_name(name: &str) -> bool {
    name.len() == "pktdump_YYYYMMDD.db".len()
        && name.starts_with("pktdump_")
        && name.ends_with(".db")
        && name[8..16].chars().all(|c| c.is_ascii_digit())
}

/// Delete a file if it exists; missing files are not treated as errors.
fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to delete file: {}", path.display())),
    }
}
