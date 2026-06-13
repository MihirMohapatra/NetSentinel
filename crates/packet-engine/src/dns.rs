use crate::models::DnsEvent;
use std::net::IpAddr;
use chrono::Utc;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct DnsParser;

impl DnsParser {
    pub fn parse(data: &[u8]) -> Option<DnsEvent> {
        if data.len() < 12 {
            return None;
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let questions = u16::from_be_bytes([data[4], data[5]]);
        let answers = u16::from_be_bytes([data[6], data[7]]);
        let _authority = u16::from_be_bytes([data[8], data[9]]);
        let _additional = u16::from_be_bytes([data[10], data[11]]);
        let response_code = flags & 0x0F;

        if questions == 0 {
            return None;
        }

        let mut offset = 12;
        let mut query_domain = String::new();

        for _ in 0..questions {
            if let Some((domain, new_offset)) = Self::parse_domain_name(data, offset) {
                query_domain = domain;
                offset = new_offset;
            }
            offset += 4;
        }

        let mut response_ips = Vec::new();
        for _ in 0..answers {
            if offset >= data.len() {
                break;
            }
            offset += 2;
            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 8;
            let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            
            if rtype == 1 && rdlength == 4 && offset + 4 <= data.len() {
                let ip = IpAddr::from([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                response_ips.push(ip);
            }
            offset += rdlength as usize;
        }

        Some(DnsEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            query_domain,
            query_type: 1,
            response_ips,
            response_code,
            process_id: None,
            process_name: None,
        })
    }

    fn parse_domain_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let original_offset = offset;

        loop {
            if offset >= data.len() {
                return None;
            }

            let len = data[offset];
            if len == 0 {
                offset += 1;
                break;
            }

            if len & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    return None;
                }
                let pointer = ((len & 0x3F) as usize) << 8 | data[offset + 1] as usize;
                if !jumped {
                    offset = pointer;
                    jumped = true;
                } else {
                    return None;
                }
                continue;
            }

            offset += 1;
            if offset + len as usize > data.len() {
                return None;
            }
            let label = String::from_utf8_lossy(&data[offset..offset + len as usize]).to_string();
            labels.push(label);
            offset += len as usize;
        }

        if !jumped {
            offset = original_offset + labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
        }

        Some((labels.join("."), offset))
    }
}