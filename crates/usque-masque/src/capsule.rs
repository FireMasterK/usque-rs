use bytes::{BufMut, Bytes, BytesMut};

/// RFC 9297 / RFC 9484 capsule types used by CONNECT-IP.
pub const CAPSULE_CONNECT_IP_DATA: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
pub const CAPSULE_CONNECT_IP_REQUEST: u64 = 0x04;

pub fn put_varint(out: &mut BytesMut, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

pub fn put_capsule(out: &mut BytesMut, capsule_type: u64, value: &[u8]) {
    put_varint(out, capsule_type);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Worst-case byte overhead of a CONNECT-IP DATA capsule with the
/// supplied payload length. Useful for pre-reserving scratch buffers.
pub const CAPSULE_OVERHEAD: usize = 3; // type varint (1) + length varint for 1500 (2)

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

/// Streaming reader for capsule-framed bodies. Stores pushed `Bytes`
/// chunks and returns CONNECT-IP DATA payloads as refcounted slices
/// that alias the underlying buffer. Already-consumed bytes are tracked
/// by an offset; the chunk chain is only compacted periodically so the
/// per-push cost is O(1).
pub struct CapsuleReader {
    chunks: Vec<Bytes>,
    /// Byte offset into the first chunk (or sum of drained lengths).
    start_in_first: usize,
}

impl CapsuleReader {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            start_in_first: 0,
        }
    }

    pub fn push(&mut self, data: Bytes) {
        if !data.is_empty() {
            self.chunks.push(data);
        }
    }

    /// Returns the next CONNECT-IP DATA payload as a `Bytes` slice that
    /// aliases the underlying buffer. Returns `None` if more bytes are
    /// needed to complete the current capsule.
    pub fn next_ip_packet(&mut self) -> Option<Bytes> {
        loop {
            let (capsule_type, t_len) = decode_varint(self.first_slice())?;
            let rest = self.first_slice().get(t_len..)?;
            let (length, l_len) = decode_varint(rest)?;
            let header_len = t_len + l_len;
            let total = header_len + length as usize;
            if self.total_len() < total {
                return None;
            }

            let value = self.slice_bytes(header_len, length as usize);

            // Advance past this capsule.
            self.skip(total);

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

    /// Drops fully-consumed leading chunks. O(1) amortized: called
    /// periodically rather than per capsule.
    pub fn compact(&mut self) {
        while let Some(first) = self.chunks.first() {
            if self.start_in_first >= first.len() {
                self.start_in_first -= first.len();
                self.chunks.remove(0);
            } else {
                break;
            }
        }
    }

    /// Number of stored body chunks. Used by callers to decide when
    /// to call `compact`.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    fn first_slice(&self) -> &[u8] {
        match self.chunks.first() {
            Some(b) => &b[self.start_in_first..],
            None => &[],
        }
    }

    fn total_len(&self) -> usize {
        self.chunks
            .iter()
            .map(|b| b.len())
            .sum::<usize>()
            .saturating_sub(self.start_in_first)
    }

    /// Return a `Bytes` slice of `length` bytes starting at the current
    /// head + `offset` bytes. The slice may span chunk boundaries; in
    /// that case we assemble a fresh `Bytes` from the two halves (still
    /// refcounted — no `memcpy` of the underlying data, just two ref
    /// bumps and a 16-byte header copy).
    fn slice_bytes(&self, offset: usize, length: usize) -> Bytes {
        let mut cursor = self.cursor_after(offset);
        let mut remaining = length;
        if let Some(first) = cursor.next() {
            if first.len() >= remaining {
                return first.slice(..remaining);
            }
            let mut out = BytesMut::with_capacity(length);
            out.extend_from_slice(&first);
            remaining -= first.len();
            for next in cursor {
                if next.len() >= remaining {
                    out.extend_from_slice(&next[..remaining]);
                    return out.freeze();
                }
                out.extend_from_slice(&next);
                remaining -= next.len();
            }
            return out.freeze();
        }
        Bytes::new()
    }

    fn skip(&mut self, mut n: usize) {
        while n > 0 {
            let head_len = match self.chunks.first() {
                Some(b) => b.len() - self.start_in_first,
                None => return,
            };
            if n < head_len {
                self.start_in_first += n;
                n = 0;
            } else {
                n -= head_len;
                self.chunks.remove(0);
                self.start_in_first = 0;
            }
        }
    }

    /// Iterator yielding contiguous `Bytes` slices starting at the
    /// current head, then advancing `offset` bytes in.
    fn cursor_after(&self, mut offset: usize) -> CursorAfter<'_> {
        let mut idx = 0;
        let mut local_start = self.start_in_first;
        // Skip past the first chunk if the offset lands inside it.
        if let Some(first) = self.chunks.first() {
            let head_len = first.len() - self.start_in_first;
            if offset < head_len {
                local_start = self.start_in_first + offset;
                offset = 0;
                idx = 0;
            } else {
                offset -= head_len;
                idx = 1;
            }
        }
        CursorAfter {
            chunks: &self.chunks,
            idx,
            local_start,
            offset_remaining: offset,
        }
    }
}

struct CursorAfter<'a> {
    chunks: &'a [Bytes],
    idx: usize,
    local_start: usize,
    offset_remaining: usize,
}

impl<'a> Iterator for CursorAfter<'a> {
    type Item = Bytes;
    fn next(&mut self) -> Option<Bytes> {
        if self.offset_remaining > 0 {
            let b = self.chunks.get(self.idx)?;
            let head_len = b.len();
            let head_effective = if self.idx == 0 {
                head_len - self.local_start
            } else {
                head_len
            };
            if self.offset_remaining < head_effective {
                let start = if self.idx == 0 {
                    self.local_start + self.offset_remaining
                } else {
                    self.offset_remaining
                };
                self.offset_remaining = 0;
                self.local_start = start;
                return Some(b.slice(start..));
            }
            self.offset_remaining -= head_effective;
            self.idx += 1;
            return self.next();
        }
        let b = self.chunks.get(self.idx)?;
        if self.idx == 0 {
            let slice = b.slice(self.local_start..);
            self.idx += 1;
            Some(slice)
        } else {
            let slice = b.clone();
            self.idx += 1;
            Some(slice)
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

    fn encode_varint_vec(mut value: u64) -> Vec<u8> {
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

    fn encode_capsule_vec(capsule_type: u64, value: &[u8]) -> Vec<u8> {
        let mut out = encode_varint_vec(capsule_type);
        out.extend_from_slice(&encode_varint_vec(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn varint_roundtrip() {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, 300);
        let (value, len) = decode_varint(&buf).unwrap();
        assert_eq!(value, 300);
        assert_eq!(len, buf.len());
    }

    #[test]
    fn read_ip_packet() {
        let packet = b"\x45\x00\x00\x1c";
        let frame = encode_capsule_vec(CAPSULE_CONNECT_IP_DATA, packet);
        let mut reader = CapsuleReader::new();
        reader.push(Bytes::from(frame));
        let out = reader.next_ip_packet().unwrap();
        assert_eq!(&out[..], packet);
    }

    #[test]
    fn skip_non_data_capsules() {
        let packet = b"\x45\x00\x00\x1c";
        let assign = encode_capsule_vec(CAPSULE_ADDRESS_ASSIGN, b"\x00");
        let data = encode_capsule_vec(CAPSULE_CONNECT_IP_DATA, packet);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&assign);
        buf.extend_from_slice(&data);
        let mut reader = CapsuleReader::new();
        reader.push(buf.freeze());
        let out = reader.next_ip_packet().unwrap();
        assert_eq!(&out[..], packet);
    }

    #[test]
    fn fragment_across_pushes() {
        let packet = b"\x45\x00\x00\x1c";
        let frame = encode_capsule_vec(CAPSULE_CONNECT_IP_DATA, packet);
        // Split the frame across two push() calls.
        let split = frame.len() / 2;
        let mut reader = CapsuleReader::new();
        reader.push(Bytes::from(frame[..split].to_vec()));
        assert!(reader.next_ip_packet().is_none());
        reader.push(Bytes::from(frame[split..].to_vec()));
        let out = reader.next_ip_packet().unwrap();
        assert_eq!(&out[..], packet);
    }

    #[test]
    fn compact_drops_drained_chunks() {
        let packet = b"\x45\x00\x00\x1c";
        let frame = encode_capsule_vec(CAPSULE_CONNECT_IP_DATA, packet);
        let mut reader = CapsuleReader::new();
        reader.push(Bytes::from(frame.clone()));
        let _ = reader.next_ip_packet().unwrap();
        reader.compact();
        assert!(reader.chunks.is_empty());
    }

    #[test]
    fn single_chunk_zero_copy_alias() {
        // When the entire capsule payload lives inside one pushed
        // `Bytes` chunk, the returned slice must alias the source
        // buffer (same `as_ptr()`).
        let packet = b"\x45\x00\x00\x1c";
        let frame = encode_capsule_vec(CAPSULE_CONNECT_IP_DATA, packet);
        let frame_bytes = Bytes::from(frame);
        // Compute the expected pointer to the payload region.
        let header_len = 1 /* type varint */ + 1 /* length varint */;
        let expected_ptr = unsafe { frame_bytes.as_ptr().add(header_len) };

        let mut reader = CapsuleReader::new();
        reader.push(frame_bytes);
        let out = reader.next_ip_packet().unwrap();
        assert_eq!(out.as_ptr(), expected_ptr);
    }
}
