/// RFC 9297 / RFC 9484 capsule types used by CONNECT-IP.
pub const CAPSULE_CONNECT_IP_DATA: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
pub const CAPSULE_CONNECT_IP_REQUEST: u64 = 0x04;

pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

pub fn decode_varint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for (i, &byte) in input.iter().enumerate() {
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

pub fn encode_capsule(capsule_type: u64, value: &[u8]) -> Vec<u8> {
    let mut out = encode_varint(capsule_type);
    out.extend_from_slice(&encode_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

pub struct CapsuleReader {
    buffer: Vec<u8>,
}

impl CapsuleReader {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_ip_packet(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buffer.is_empty() {
                return None;
            }

            let (capsule_type, t_len) = decode_varint(&self.buffer)?;
            let rest = &self.buffer[t_len..];
            let (length, l_len) = decode_varint(rest)?;
            let header_len = t_len + l_len;
            let total = header_len + length as usize;
            if self.buffer.len() < total {
                return None;
            }

            let value = self.buffer[header_len..total].to_vec();
            self.buffer.drain(..total);

            match capsule_type {
                CAPSULE_CONNECT_IP_DATA => return Some(value),
                CAPSULE_ADDRESS_ASSIGN
                | CAPSULE_ADDRESS_REQUEST
                | CAPSULE_ROUTE_ADVERTISEMENT
                | CAPSULE_CONNECT_IP_REQUEST => continue,
                _ => continue,
            }
        }
    }
}

impl Default for CapsuleReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let encoded = encode_varint(300);
        let (value, len) = decode_varint(&encoded).unwrap();
        assert_eq!(value, 300);
        assert_eq!(len, encoded.len());
    }

    #[test]
    fn read_ip_packet() {
        let packet = b"\x45\x00\x00\x1c".to_vec();
        let frame = encode_capsule(CAPSULE_CONNECT_IP_DATA, &packet);
        let mut reader = CapsuleReader::new();
        reader.push(&frame);
        assert_eq!(reader.next_ip_packet().unwrap(), packet);
    }
}
