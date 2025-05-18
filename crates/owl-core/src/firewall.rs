use nix::unistd::Uid;
use std::net::IpAddr;
use std::process::Command;

use crate::errors::FirewallError;

pub fn ensure_net_admin() -> Result<(), FirewallError> {
    if !Uid::effective().is_root() {
        return Err(FirewallError::NetAdminRequired);
    }
    Ok(())
}

pub fn block_all() -> Result<(), FirewallError> {
    let nft = Command::new("nft").args(["flush", "ruleset"]).status();
    match nft {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FirewallError::NftFailed("nft command not found".into()));
        }
        Err(e) => return Err(FirewallError::Io(e)),
        Ok(s) if !s.success() => return Err(FirewallError::NftFailed("flush ruleset".into())),
        _ => {}
    }
    let nft = Command::new("nft")
        .args(["add", "table", "inet", "owl"])
        .status();
    match nft {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FirewallError::NftFailed("nft command not found".into()));
        }
        Err(e) => return Err(FirewallError::Io(e)),
        Ok(s) if !s.success() => return Err(FirewallError::NftFailed("add table".into())),
        _ => {}
    }
    let nft = Command::new("nft")
        .args([
            "add", "chain", "inet", "owl", "input", "{", "type", "filter", "hook", "input",
            "priority", "0;", "policy", "drop;", "}",
        ])
        .status();
    match nft {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FirewallError::NftFailed("nft command not found".into()));
        }
        Err(e) => return Err(FirewallError::Io(e)),
        Ok(s) if !s.success() => return Err(FirewallError::NftFailed("add chain".into())),
        _ => {}
    }
    Ok(())
}

pub fn add_allowed(ips: &std::collections::HashSet<IpAddr>) -> Result<(), FirewallError> {
    for ip in ips {
        let nft = Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "owl",
                "input",
                if ip.is_ipv6() { "ip6" } else { "ip" },
                "saddr",
                &ip.to_string(),
                "accept",
            ])
            .status();
        match nft {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FirewallError::NftFailed("nft command not found".into()));
            }
            Err(e) => return Err(FirewallError::Io(e)),
            Ok(s) if !s.success() => {
                return Err(FirewallError::NftFailed(format!("add rule for {}", ip)));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn reload_allowed_ips(cfg: &crate::Config) -> Result<(), FirewallError> {
    block_all()?;
    add_allowed(&crate::collect_ips(cfg))?;
    Ok(())
}
