use thiserror::Error;

#[derive(Debug, Error)]
pub enum OwlError {
    #[error("設定ファイルが見つかりません: {0}")]
    ConfigNotFound(String),
    #[error("設定ファイルの読み込みに失敗しました: {0}")]
    ConfigReadFailed(String),
    #[error("設定ファイルのパースに失敗しました: {0}")]
    ConfigParseFailed(String),
    #[error(transparent)]
    Firewall(#[from] FirewallError),
    #[error(transparent)]
    Tun(#[from] TunError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("NET_ADMIN 権限が必要 (root もしくは cap‑add)")]
    NetAdminRequired,
    #[error("nft コマンド実行失敗: {0}")]
    NftFailed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN デバイス操作失敗: {0}")]
    TunFailed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
