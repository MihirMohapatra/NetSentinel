use crate::models::NetworkEvent;

#[derive(Clone, Copy)]
pub struct TcpParser;

impl TcpParser {
    pub fn enrich(&self, _event: &mut NetworkEvent, _payload: &[u8]) {
    }

    pub fn parse_flags(&self, flags: u8) -> TcpFlags {
        TcpFlags {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
            ece: flags & 0x40 != 0,
            cwr: flags & 0x80 != 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn is_connection_start(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_connection_established(&self) -> bool {
        self.syn && self.ack
    }

    pub fn is_connection_end(&self) -> bool {
        self.fin || self.rst
    }
}