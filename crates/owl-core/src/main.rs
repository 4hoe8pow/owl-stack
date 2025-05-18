use std::net::IpAddr;
use std::{collections::HashSet, fs, path::PathBuf};

use clap::{Parser, Subcommand};
use log::info;
use serde::Deserialize;

mod errors;
mod firewall;
mod tun;

use errors::OwlError;

/// CLI 定義
#[derive(Parser)]
#[command(
    name = "owlctl",
    author,
    version,
    about = "Owl‑Core Runtime Controller"
)]
struct Cli {
    /// サブコマンド
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 設定をチェックして終了
    Check {
        /// 設定ファイル (TOML)
        #[arg(value_name = "FILE")]
        config: PathBuf,
    },
    /// デーモンとして起動
    Start {
        /// 設定ファイル (TOML)
        #[arg(value_name = "FILE")]
        config: PathBuf,
    },
    /// 実行中プロセスにリロード信号
    Reload {
        /// 設定ファイル (TOML)
        #[arg(value_name = "FILE")]
        config: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct Config {
    interface: Interface,
    peers: Vec<Peer>,
}

#[derive(Debug, Deserialize)]
struct Interface {
    listen_port: u16,
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct Peer {
    public_key: String,
    allowed_ips: Vec<IpAddr>,
}

#[tokio::main]
async fn main() -> Result<(), OwlError> {
    env_logger::init();
    let cli = Cli::parse();

    // 権限チェック
    firewall::ensure_net_admin()?;

    match cli.command {
        Commands::Check { config } => {
            // load & validate once
            let cfg = load_config(&config)?;
            info!("構文と整合性チェック完了: 問題なし");
            return Ok(());
        }
        Commands::Reload { config } => {
            let cfg = load_config(&config)?;
            firewall::reload_allowed_ips(&cfg)?;
            tun::signal_reload().await?;
            info!("リロードシグナル送信完了");
            return Ok(());
        }
        Commands::Start { config } => {
            let cfg = load_config(&config)?;
            startup(cfg).await?;
        }
    }
    Ok(())
}

/// 起動フロー
async fn startup(cfg: Config) -> Result<(), OwlError> {
    // 1) ファイアウォール初期化
    firewall::block_all()?;
    firewall::add_allowed(&collect_ips(&cfg))?;

    // 2) TUN / WireGuard スタック
    tun::spawn_tun(cfg).await?;

    info!("owl-core running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await.map_err(anyhow::Error::from)?;
    info!("Shutting down…");
    Ok(())
}

/// helper
fn load_config(path: &PathBuf) -> Result<Config, OwlError> {
    let text = fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => OwlError::ConfigNotFound(path.display().to_string()),
        _ => OwlError::ConfigReadFailed(format!("{:?}: {}", path, e)),
    })?;
    let cfg: Config =
        toml::from_str(&text).map_err(|e| OwlError::ConfigParseFailed(e.to_string()))?;
    Ok(cfg)
}
fn collect_ips(cfg: &Config) -> HashSet<IpAddr> {
    cfg.peers
        .iter()
        .flat_map(|p| p.allowed_ips.iter().cloned())
        .collect()
}
