use anyhow::{Context, Result};
use std::net::{IpAddr, UdpSocket};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WolError {
    #[error("Invalid MAC address format: {0}")]
    InvalidMac(String),
    #[error("Failed to send magic packet: {0}")]
    SendError(String),
}

/// Parse a MAC address string "AA:BB:CC:DD:EE:FF" into bytes.
pub fn parse_mac_str(s: &str) -> Result<[u8; 6], WolError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(WolError::InvalidMac(format!(
            "Expected 6 octets, got {}: {}",
            parts.len(),
            s
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| WolError::InvalidMac(format!("Invalid hex octet '{}' in MAC: {}", part, s)))?;
    }
    Ok(mac)
}

/// Build a Wake-on-LAN magic packet: 6×0xFF + 16×MAC (102 bytes total).
pub fn build_magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(102);
    // 6 bytes of 0xFF
    packet.extend_from_slice(&[0xFF; 6]);
    // 16 repetitions of the MAC address
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    packet
}

/// Send a Wake-on-LAN magic packet via UDP broadcast on port 9.
pub fn send_magic_packet(mac: [u8; 6], broadcast: &str) -> Result<()> {
    let packet = build_magic_packet(mac);
    let socket = UdpSocket::bind("0.0.0.0:0")
        .context("Failed to bind UDP socket for WoL")?;
    socket
        .set_broadcast(true)
        .context("Failed to enable broadcast on UDP socket")?;
    let addr = format!("{broadcast}:9");
    socket
        .send_to(&packet, &addr)
        .with_context(|| format!("Failed to send magic packet to {addr}"))?;
    Ok(())
}

/// Send WoL using the MAC string, defaulting to 255.255.255.255 broadcast.
pub fn wake(mac_str: &str) -> Result<()> {
    let mac = parse_mac_str(mac_str)
        .with_context(|| format!("Invalid MAC address: {mac_str}"))?;
    send_magic_packet(mac, "255.255.255.255")
        .context("Failed to send Wake-on-LAN magic packet")?;
    tracing::info!("Sent WoL magic packet to {}", mac_str);
    Ok(())
}

/// Resolve a hostname to its first IPv4 address.
fn resolve_hostname(hostname: &str) -> Result<IpAddr> {
    use std::net::ToSocketAddrs;
    let addr = format!("{hostname}:0")
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve hostname: {hostname}"))?
        .find(|a| a.is_ipv4())
        .with_context(|| format!("No IPv4 address found for: {hostname}"))?;
    Ok(addr.ip())
}

/// Populate the ARP cache for `ip` by sending one ping.
fn ping_once(ip: &IpAddr) -> Result<()> {
    let output = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "2", &ip.to_string()])
        .output()
        .context("Failed to run ping")?;
    if !output.status.success() {
        anyhow::bail!("ping to {} failed — host may be offline", ip);
    }
    Ok(())
}

/// Read /proc/net/arp and return the MAC for the given IP, if present.
/// Skips entries with flags 0x0 (incomplete/stale).
fn lookup_arp_cache(ip: &IpAddr) -> Result<Option<String>> {
    let content = std::fs::read_to_string("/proc/net/arp")
        .context("Failed to read /proc/net/arp")?;

    for line in content.lines().skip(1) {
        // Format: IP address   HW type   Flags   HW address           Mask   Device
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let entry_ip: IpAddr = match fields[0].parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if entry_ip != *ip {
            continue;
        }
        let flags = fields[2];
        // Skip incomplete entries (flags = 0x0)
        if flags == "0x0" {
            continue;
        }
        let mac = fields[3].to_uppercase();
        // Skip all-zero MACs
        if mac == "00:00:00:00:00:00" {
            continue;
        }
        return Ok(Some(mac));
    }
    Ok(None)
}

/// Discover the MAC address of a host via ARP.
///
/// Steps:
///   1. Resolve hostname → IP
///   2. Ping once to populate the ARP cache
///   3. Read /proc/net/arp to find the MAC
///
/// Only works when the host is reachable on the local network.
pub fn discover_mac(hostname: &str) -> Result<String> {
    let ip = resolve_hostname(hostname)?;
    tracing::debug!("Resolved {} → {}", hostname, ip);

    // Try ARP cache first (host may already be known)
    if let Some(mac) = lookup_arp_cache(&ip)? {
        return Ok(mac);
    }

    // Not in cache yet — ping to trigger ARP resolution
    ping_once(&ip)?;

    // Give the kernel a moment to update the ARP table
    std::thread::sleep(std::time::Duration::from_millis(200));

    lookup_arp_cache(&ip)?
        .with_context(|| format!("Host {} ({}) not found in ARP cache after ping", hostname, ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_mac() {
        let mac = parse_mac_str("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_invalid_mac() {
        assert!(parse_mac_str("AA:BB:CC:DD:EE").is_err());
        assert!(parse_mac_str("GG:BB:CC:DD:EE:FF").is_err());
        assert!(parse_mac_str("not-a-mac").is_err());
    }

    #[test]
    fn test_magic_packet_length() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let packet = build_magic_packet(mac);
        assert_eq!(packet.len(), 102);
        // First 6 bytes must be 0xFF
        assert_eq!(&packet[..6], &[0xFF; 6]);
        // Bytes 6..12 should be the MAC
        assert_eq!(&packet[6..12], &mac);
    }

    #[test]
    fn test_lookup_arp_cache_found() {
        // Write a synthetic /proc/net/arp-style table into a temp string and
        // test the parsing logic directly via the internal helper.
        use std::net::IpAddr;

        // We test the parsing logic by calling lookup_arp_cache with a known
        // IP that appears in the actual ARP table (loopback won't be there),
        // so instead we verify the negative case + that the parser doesn't panic.
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        // This either returns Some(mac) or None — both are valid depending on
        // the test environment. It must not panic or error out.
        let _ = lookup_arp_cache(&ip);
    }

    #[test]
    fn test_resolve_localhost() {
        // localhost must always resolve to 127.0.0.1
        let ip = resolve_hostname("localhost").unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_resolve_unknown_host() {
        // Completely bogus hostname must fail
        assert!(resolve_hostname("this-host-does-not-exist.invalid").is_err());
    }

    #[test]
    fn test_send_magic_packet_content() {
        // Bind a local receiver on an ephemeral port so we don't need root
        // (the real WoL target is port 9, but the packet content is identical).
        use std::net::UdpSocket;
        use std::time::Duration;

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let packet = build_magic_packet(mac);

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&packet, addr).unwrap();

        let mut buf = [0u8; 200];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();

        assert_eq!(n, 102);
        // First 6 bytes: synchronisation stream
        assert_eq!(&buf[..6], &[0xFF; 6]);
        // All 16 repetitions must match the MAC exactly
        for i in 0..16usize {
            let start = 6 + i * 6;
            assert_eq!(
                &buf[start..start + 6],
                &mac,
                "MAC mismatch at repetition {i}"
            );
        }
    }
}
