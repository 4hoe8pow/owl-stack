use crate::Config;
use crate::errors::TunError;

pub async fn spawn_tun(cfg: Config) -> Result<(), TunError> {
    // 実際には WireGuard ユーザ空間をここで spawn
    // 例: `wg-userspace --config /dev/fd/3`
    println!("(TUN mock) listen on {}", cfg.interface.listen_port);
    Ok(())
}

pub async fn signal_reload() -> Result<(), TunError> {
    // PID ファイルを読んで SIGHUP 等を送る想定
    Ok(())
}
