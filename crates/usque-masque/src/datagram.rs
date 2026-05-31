use bytes::Bytes;
use etherparse::IpHeaders;

use crate::capsule::{encode_capsule, encode_varint, decode_varint, CAPSULE_CONNECT_IP_DATA};

const CONTEXT_ID: u64 = 0;

/// Payload for tokio-quiche datagram flows (quarter stream ID is added by the driver).
pub fn encode_h3_datagram_payload(packet: &mut [u8]) -> anyhow::Result<Bytes> {
    prepare_ip_packet(packet)?;
    Ok(Bytes::from(encode_h3_datagram_payload_bytes(packet)?))
}

fn encode_h3_datagram_payload_bytes(packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = encode_varint(CONTEXT_ID);
    out.extend_from_slice(packet);
    Ok(out)
}

/// Parse CONNECT-IP payload after the quarter stream ID prefix.
pub fn decode_h3_datagram_payload(data: &[u8]) -> Option<Vec<u8>> {
    let (context, c_len) = decode_varint(data)?;
    if context != CONTEXT_ID {
        return None;
    }
    let payload = data.get(c_len..)?;
    if payload.is_empty() {
        return None;
    }
    Some(payload.to_vec())
}

/// Wrap an IP packet for HTTP/2 CONNECT-IP (DATAGRAM capsule type 0).
pub fn encode_h2_datagram_capsule(packet: &mut [u8]) -> anyhow::Result<Bytes> {
    prepare_ip_packet(packet)?;
    Ok(Bytes::from(encode_capsule(CAPSULE_CONNECT_IP_DATA, packet)))
}

fn prepare_ip_packet(packet: &mut [u8]) -> anyhow::Result<()> {
    if packet.is_empty() {
        anyhow::bail!("empty IP packet");
    }
    match packet[0] >> 4 {
        4 => {
            let (mut headers, _) = IpHeaders::from_slice(packet)
                .map_err(|err| anyhow::anyhow!("failed to parse IPv4 packet: {err}"))?;
            let IpHeaders::Ipv4(header, _) = &mut headers else {
                anyhow::bail!("failed to decode IPv4 header");
            };
            if header.time_to_live <= 1 {
                anyhow::bail!("IPv4 TTL too small: {}", header.time_to_live);
            }
            header.time_to_live -= 1;
            let header_len = header.header_len();
            if packet.len() < header_len {
                anyhow::bail!("IPv4 header too short");
            }
            let mut cursor = std::io::Cursor::new(&mut packet[..header_len]);
            header.write(&mut cursor)
                .map_err(|err| anyhow::anyhow!("failed to write IPv4 header: {err}"))?;
        }
        6 => {
            if packet.len() < 40 {
                anyhow::bail!("IPv6 packet too short");
            }
            let hop = packet[7];
            if hop <= 1 {
                anyhow::bail!("IPv6 hop limit too small: {hop}");
            }
            packet[7] -= 1;
        }
        version => anyhow::bail!("unknown IP version: {version}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_datagram_roundtrip() {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        ];
        let encoded = encode_h3_datagram_payload(&mut packet).unwrap();
        let decoded = decode_h3_datagram_payload(&encoded).unwrap();
        assert_eq!(decoded[8], 0x3f); // TTL decremented
    }
}
