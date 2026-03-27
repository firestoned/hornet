//! AST types for RFC 1035 zone files and common extensions.
//!
//! The entry point is [`ZoneFile`], which contains a list of [`Entry`]s.

use std::net::{Ipv4Addr, Ipv6Addr};

// ── Zone file root ─────────────────────────────────────────────────────────────

/// A fully parsed zone file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ZoneFile {
    pub entries: Vec<Entry>,
}

impl ZoneFile {
    /// Return all [`ResourceRecord`]s in entry order.
    pub fn records(&self) -> impl Iterator<Item = &ResourceRecord> {
        self.entries.iter().filter_map(|e| match e {
            Entry::Record(r) => Some(r),
            _ => None,
        })
    }
}

/// A single logical line in a zone file.
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    Origin(Name),
    Ttl(u32),
    Include { file: String, origin: Option<Name> },
    Generate(GenerateDirective),
    Record(ResourceRecord),
    Blank,
}

// ── Names ─────────────────────────────────────────────────────────────────────

/// A DNS name — either absolute (ends with `.`) or relative.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name(pub String);

impl Name {
    pub fn new(s: impl Into<String>) -> Self {
        Name(s.into())
    }
    #[must_use]
    pub fn is_at(&self) -> bool {
        self.0 == "@"
    }
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.0.ends_with('.')
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Name {
    fn from(s: &str) -> Self {
        Name(s.to_owned())
    }
}

// ── Resource record ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRecord {
    pub name: Option<Name>,
    pub ttl: Option<u32>,
    pub class: Option<RecordClass>,
    pub rdata: RData,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordClass {
    In,
    Hs,
    Chaos,
    Any,
}

impl std::fmt::Display for RecordClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordClass::In => write!(f, "IN"),
            RecordClass::Hs => write!(f, "HS"),
            RecordClass::Chaos => write!(f, "CHAOS"),
            RecordClass::Any => write!(f, "ANY"),
        }
    }
}

// ── RData ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    Ns(Name),
    Cname(Name),
    Soa(SoaData),
    Mx(MxData),
    Ptr(Name),
    Hinfo { cpu: String, os: String },
    Txt(Vec<String>),
    Aaaa(Ipv6Addr),
    Srv(SrvData),
    Caa(CaaData),
    Sshfp(SshfpData),
    Tlsa(TlsaData),
    Naptr(NaptrData),
    Loc(LocData),
    Ds(DsData),
    Dnskey(DnskeyData),
    Rrsig(RrsigData),
    Nsec(NsecData),
    Nsec3(Nsec3Data),
    Nsec3param(Nsec3paramData),
    Https(SvcbData),
    Svcb(SvcbData),
    Aname(Name),
    Unknown { rtype: String, data: String },
}

impl RData {
    #[must_use]
    pub fn rtype(&self) -> &str {
        match self {
            RData::A(_) => "A",
            RData::Ns(_) => "NS",
            RData::Cname(_) => "CNAME",
            RData::Soa(_) => "SOA",
            RData::Mx(_) => "MX",
            RData::Ptr(_) => "PTR",
            RData::Hinfo { .. } => "HINFO",
            RData::Txt(_) => "TXT",
            RData::Aaaa(_) => "AAAA",
            RData::Srv(_) => "SRV",
            RData::Caa(_) => "CAA",
            RData::Sshfp(_) => "SSHFP",
            RData::Tlsa(_) => "TLSA",
            RData::Naptr(_) => "NAPTR",
            RData::Loc(_) => "LOC",
            RData::Ds(_) => "DS",
            RData::Dnskey(_) => "DNSKEY",
            RData::Rrsig(_) => "RRSIG",
            RData::Nsec(_) => "NSEC",
            RData::Nsec3(_) => "NSEC3",
            RData::Nsec3param(_) => "NSEC3PARAM",
            RData::Https(_) => "HTTPS",
            RData::Svcb(_) => "SVCB",
            RData::Aname(_) => "ANAME",
            RData::Unknown { rtype, .. } => rtype,
        }
    }
}

// ── Per-type structs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct SoaData {
    pub mname: Name,
    pub rname: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MxData {
    pub preference: u16,
    pub exchange: Name,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Name,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaaData {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SshfpData {
    pub algorithm: u8,
    pub fp_type: u8,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlsaData {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NaptrData {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub service: String,
    pub regexp: String,
    pub replacement: Name,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocData {
    pub d_lat: u32,
    pub m_lat: u32,
    pub s_lat: f64,
    pub lat_dir: LatDir,
    pub d_lon: u32,
    pub m_lon: u32,
    pub s_lon: f64,
    pub lon_dir: LonDir,
    pub altitude: f64,
    pub size: f64,
    pub horiz_pre: f64,
    pub vert_pre: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatDir {
    N,
    S,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LonDir {
    E,
    W,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnskeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RrsigData {
    pub type_covered: String,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub sig_expiration: String,
    pub sig_inception: String,
    pub key_tag: u16,
    pub signer_name: Name,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NsecData {
    pub next_domain: Name,
    pub type_bitmap: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Nsec3Data {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: String,
    pub next_hashed: String,
    pub type_bitmap: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Nsec3paramData {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SvcbData {
    pub priority: u16,
    pub target: Name,
    pub params: Vec<SvcParam>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SvcParam {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenerateDirective {
    pub range_start: u32,
    pub range_end: u32,
    pub range_step: Option<u32>,
    pub lhs: String,
    pub ttl: Option<u32>,
    pub class: Option<RecordClass>,
    pub rtype: String,
    pub rhs: String,
}
