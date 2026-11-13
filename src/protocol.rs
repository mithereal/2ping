use crate::crypto::SecurityConfig;
use rand::RngCore;
use std::io::{Cursor, Read};

pub const MAGIC_NUMBER: u16 = 0x3250; // "2P"
pub const DEFAULT_PORT: u16 = 15998;
pub const MIN_HEADER_LEN: usize = 12;

pub mod opcodes {
    pub const REPLY_REQUESTED: u16 = 0x0001;
    pub const IN_REPLY_TO: u16 = 0x0002;
    pub const COURTESY_EXPIRES: u16 = 0x0004;
    pub const PING_TIME: u16 = 0x0008;
    pub const HOST_LATENCY: u16 = 0x0010;
    pub const INVESTIGATE: u16 = 0x0020;
    pub const HMAC: u16 = 0x0040;
    pub const ENCRYPTED: u16 = 0x8000;
}

#[derive(Debug, Clone, Default)]
pub struct Packet {
    pub message_id: [u8; 6],
    pub reply_requested: bool,
    pub in_reply_to: Option<[u8; 6]>,
    pub courtesy_expires: Vec<[u8; 6]>,
    pub ping_time_us: Option<u32>,
    pub host_latency_us: Option<u32>,
    pub investigate: Vec<[u8; 6]>,
    pub min_size: usize,
    pub pad_pattern: Vec<u8>,
}

impl Packet {
    pub fn new() -> Self {
        let mut message_id = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut message_id);
        Self {
            message_id,
            min_size: 128,
            ..Default::default()
        }
    }

    pub fn id_hex(&self) -> String {
        hex_id(&self.message_id)
    }

    /// Serializes inner opcodes (0x0002 .. 0x0020) without HMAC or Encryption.
    fn encode_inner_opcodes(&self) -> (u16, Vec<u8>) {
        let mut flags: u16 = 0;
        let mut data = Vec::new();

        if self.reply_requested {
            flags |= opcodes::REPLY_REQUESTED;
        }

        if let Some(reply_id) = &self.in_reply_to {
            flags |= opcodes::IN_REPLY_TO;
            data.extend_from_slice(&6u16.to_be_bytes());
            data.extend_from_slice(reply_id);
        }

        if !self.courtesy_expires.is_empty() {
            flags |= opcodes::COURTESY_EXPIRES;
            let len = (self.courtesy_expires.len() * 6) as u16;
            data.extend_from_slice(&len.to_be_bytes());
            for id in &self.courtesy_expires {
                data.extend_from_slice(id);
            }
        }

        if let Some(rtt_us) = self.ping_time_us {
            flags |= opcodes::PING_TIME;
            data.extend_from_slice(&4u16.to_be_bytes());
            data.extend_from_slice(&rtt_us.to_be_bytes());
        }

        if let Some(lat_us) = self.host_latency_us {
            flags |= opcodes::HOST_LATENCY;
            data.extend_from_slice(&4u16.to_be_bytes());
            data.extend_from_slice(&lat_us.to_be_bytes());
        }

        if !self.investigate.is_empty() {
            flags |= opcodes::INVESTIGATE;
            let len = (self.investigate.len() * 6) as u16;
            data.extend_from_slice(&len.to_be_bytes());
            for id in &self.investigate {
                data.extend_from_slice(id);
            }
        }

        (flags, data)
    }

    /// Encodes the packet into wire bytes, applying AES-256-CBC encryption and/or HMAC.
    pub fn encode(&self, sec: &SecurityConfig) -> Vec<u8> {
        let (mut flags, mut opcode_data) = self.encode_inner_opcodes();

        // 1. Encrypt inner flags + opcode payload if --encrypt is enabled
        if sec.encrypt_key.is_some() {
            let mut plaintext = Vec::with_capacity(2 + opcode_data.len());
            plaintext.extend_from_slice(&flags.to_be_bytes());
            plaintext.extend_from_slice(&opcode_data);

            let encrypted_blob = sec
                .encrypt_aes256_cbc(&plaintext)
                .expect("Encryption key present");

            // Outer flags clear plaintext opcode bits and set ENCRYPTED (0x8000)
            flags = opcodes::ENCRYPTED;
            opcode_data.clear();
            opcode_data.extend_from_slice(&(encrypted_blob.len() as u16).to_be_bytes());
            opcode_data.extend_from_slice(&encrypted_blob);
        }

        // 2. Reserve HMAC opcode slot (0x0040) before ENCRYPTED (0x8000) in ascending bit order
        let mut hmac_offset = None;
        let mut hmac_field_len = 0usize;

        if let Some(digest) = sec.auth_digest {
            flags |= opcodes::HMAC;
            hmac_field_len = 1 + digest.tag_len();

            // Insert HMAC TLV before ENCRYPTED TLV if ENCRYPTED is set
            let insert_pos = if (flags & opcodes::ENCRYPTED) != 0 {
                0
            } else {
                opcode_data.len()
            };

            let mut hmac_tlv = Vec::with_capacity(2 + hmac_field_len);
            hmac_tlv.extend_from_slice(&(hmac_field_len as u16).to_be_bytes());
            hmac_tlv.resize(2 + hmac_field_len, 0x00);

            opcode_data.splice(insert_pos..insert_pos, hmac_tlv);
            hmac_offset = Some(MIN_HEADER_LEN + insert_pos + 2);
        }

        // 3. Assemble header + opcodes + padding
        let mut buf = Vec::with_capacity(self.min_size.max(MIN_HEADER_LEN + opcode_data.len()));
        buf.extend_from_slice(&MAGIC_NUMBER.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&self.message_id);
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&opcode_data);

        if buf.len() < self.min_size {
            let pad_needed = self.min_size - buf.len();
            if self.pad_pattern.is_empty() {
                buf.resize(self.min_size, 0x00);
            } else {
                for i in 0..pad_needed {
                    buf.push(self.pad_pattern[i % self.pad_pattern.len()]);
                }
            }
        }

        // 4. Compute HMAC over entire frame (with checksum and HMAC value zeroed)
        if let Some(offset) = hmac_offset {
            let tag = sec.compute_hmac(&buf).expect("HMAC key present");
            buf[offset..offset + hmac_field_len].copy_from_slice(&tag);
        }

        // 5. Compute and insert 16-bit one's complement checksum
        let csum = compute_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());

        buf
    }

    /// Decodes a raw UDP packet, verifying checksum, HMAC authenticity, and decrypting if needed.
    pub fn decode(data: &[u8], sec: &SecurityConfig) -> Result<Self, &'static str> {
        if data.len() < MIN_HEADER_LEN {
            return Err("Packet too short");
        }

        let magic = u16::from_be_bytes([data[0], data[1]]);
        if magic != MAGIC_NUMBER {
            return Err("Invalid magic number");
        }

        let packet_csum = u16::from_be_bytes([data[2], data[3]]);
        if packet_csum != 0 {
            let mut verify_buf = data.to_vec();
            verify_buf[2] = 0;
            verify_buf[3] = 0;
            if compute_checksum(&verify_buf) != packet_csum {
                return Err("Checksum mismatch");
            }
        }

        let mut message_id = [0u8; 6];
        message_id.copy_from_slice(&data[4..10]);
        let outer_flags = u16::from_be_bytes([data[10], data[11]]);

        // Enforce local security policy
        if sec.auth_key.is_some() && (outer_flags & opcodes::HMAC) == 0 {
            return Err("Rejected unauthenticated packet (--auth required)");
        }
        if sec.encrypt_key.is_some() && (outer_flags & opcodes::ENCRYPTED) == 0 {
            return Err("Rejected unencrypted packet (--encrypt required)");
        }

        let mut cursor = Cursor::new(&data[12..]);
        let mut hmac_span: Option<(usize, Vec<u8>)> = None;
        let mut encrypted_blob: Option<Vec<u8>> = None;
        let mut outer_opcodes = Vec::new();

        for bit in 1..16 {
            let flag = 1u16 << bit;
            if (outer_flags & flag) == 0 {
                continue;
            }

            let mut len_bytes = [0u8; 2];
            if cursor.read_exact(&mut len_bytes).is_err() {
                return Err("Truncated opcode length");
            }
            let field_len = u16::from_be_bytes(len_bytes) as usize;
            let value_start = MIN_HEADER_LEN + cursor.position() as usize;

            let mut payload = vec![0u8; field_len];
            if cursor.read_exact(&mut payload).is_err() {
                return Err("Truncated opcode data");
            }

            match flag {
                opcodes::HMAC => {
                    hmac_span = Some((value_start, payload));
                }
                opcodes::ENCRYPTED => {
                    encrypted_blob = Some(payload);
                }
                _ => {
                    outer_opcodes.push((flag, payload));
                }
            }
        }

        // Verify HMAC before decrypting (Encrypt-then-MAC protection against padding oracles)
        if let Some((offset, tag_bytes)) = hmac_span {
            if sec.auth_key.is_none() {
                return Err("Received HMAC packet without --auth key configured");
            }
            let mut auth_buf = data.to_vec();
            auth_buf[2] = 0;
            auth_buf[3] = 0;
            for b in &mut auth_buf[offset..offset + tag_bytes.len()] {
                *b = 0;
            }
            if !sec.verify_hmac(&auth_buf, &tag_bytes) {
                return Err("HMAC authentication failed");
            }
        }

        let mut pkt = Packet {
            message_id,
            reply_requested: (outer_flags & opcodes::REPLY_REQUESTED) != 0,
            ..Default::default()
        };

        // Decrypt inner flags and opcodes if ENCRYPTED flag was set
        if let Some(blob) = encrypted_blob {
            let plaintext = sec.decrypt_aes256_cbc(&blob)?;
            if plaintext.len() < 2 {
                return Err("Decrypted payload too short");
            }
            let inner_flags = u16::from_be_bytes([plaintext[0], plaintext[1]]);
            pkt.reply_requested = (inner_flags & opcodes::REPLY_REQUESTED) != 0;

            let mut inner_cursor = Cursor::new(&plaintext[2..]);
            for bit in 1..16 {
                let flag = 1u16 << bit;
                if (inner_flags & flag) == 0 {
continue;
}
let mut len_bytes = [0u8; 2];
if inner_cursor.read_exact(&mut len_bytes).is_err() {
return Err("Truncated decrypted opcode length");
}
let field_len = u16::from_be_bytes(len_bytes) as usize;
let mut payload = vec![0u8; field_len];
if inner_cursor.read_exact(&mut payload).is_err() {
return Err("Truncated decrypted opcode data");
}
pkt.apply_opcode(flag, &payload);
}
} else {
for (flag, payload) in outer_opcodes {
pkt.apply_opcode(flag, &payload);
}
}
Ok(pkt)
}
fn apply_opcode(&mut self, flag: u16, payload: &[u8]) {
match flag {
opcodes::IN_REPLY_TO if payload.len() >= 6 => {
let mut id = [0u8; 6];
id.copy_from_slice(&payload[..6]);
self.in_reply_to = Some(id);
}
opcodes::COURTESY_EXPIRES => {
for chunk in payload.chunks_exact(6) {
let mut id = [0u8; 6];
id.copy_from_slice(chunk);
self.courtesy_expires.push(id);
}
}
opcodes::PING_TIME if payload.len() >= 4 => {
self.ping_time_us = Some(u32::from_be_bytes([
payload[0], payload[1], payload[2], payload[3],
]));
}
opcodes::HOST_LATENCY if payload.len() >= 4 => {
self.host_latency_us = Some(u32::from_be_bytes([
payload[0], payload[1], payload[2], payload[3],
]));
}
opcodes::INVESTIGATE => {
for chunk in payload.chunks_exact(6) {
let mut id = [0u8; 6];
id.copy_from_slice(chunk);
self.investigate.push(id);
}
}
_ => {}
}
}
}
pub fn hex_id(id: &[u8; 6]) -> String {
format!(
"{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
id[0], id[1], id[2], id[3], id[4], id[5]
)
}
fn compute_checksum(data: &[u8]) -> u16 {
let mut sum: u32 = 0;
let mut chunks = data.chunks_exact(2);
for chunk in &mut chunks {
sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
}
if let Some(&rem) = chunks.remainder().first() {
sum += (rem as u32) << 8;
}
while (sum >> 16) != 0 {
sum = (sum & 0xFFFF) + (sum >> 16);
}
let res = !(sum as u16);
if res == 0 {
0xFFFF
} else {
res
}
}