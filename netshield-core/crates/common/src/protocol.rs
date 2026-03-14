use serde::{Deserialize, Serialize};
use std::fmt;

/// Network protocol identified from packet headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Other => write!(f, "other"),
        }
    }
}

impl Protocol {
    /// Map IP protocol number to enum variant.
    #[inline]
    pub fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn from_ip_protocol_maps_correctly() {
        assert_eq!(Protocol::from_ip_protocol(6), Protocol::Tcp);
        assert_eq!(Protocol::from_ip_protocol(17), Protocol::Udp);
        assert_eq!(Protocol::from_ip_protocol(1), Protocol::Icmp);
        assert_eq!(Protocol::from_ip_protocol(47), Protocol::Other);
    }

    #[test]
    fn display_is_lowercase() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
    }

    #[test]
    fn serde_roundtrip() {
        let proto = Protocol::Tcp;
        let json = serde_json::to_string(&proto).unwrap();
        assert_eq!(json, "\"tcp\"");
        let back: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(back, proto);
    }
}
