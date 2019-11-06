use crate::{sign::encode_with_hex, DATE_FORMAT, HMAC_256};
use bytes::Bytes;
use chrono::{format::ParseError, Date, DateTime, NaiveDate, NaiveDateTime, Utc};
use eliza_error::Error;
use http::{header::HeaderName, HeaderMap, Method, Request};
use serde_urlencoded as qs;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
    str::FromStr,
};

pub(crate) trait AsSigV4 {
    fn fmt(&self) -> String;
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct CanonicalRequest {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) params: String,
    pub(crate) headers: HeaderMap,
    pub(crate) signed_headers: SignedHeaders,
    pub(crate) payload_hash: String,
}

impl TryFrom<Request<()>> for CanonicalRequest {
    type Error = Error;
    fn try_from(req: Request<()>) -> Result<Self, Self::Error> {
        let mut creq = CanonicalRequest::default();
        creq.method = req.method().clone();
        creq.path = req.uri().path_and_query().unwrap().path().to_string();

        if let Some(pq) = req.uri().path_and_query() {
            if let Some(path) = pq.query() {
                let params: BTreeMap<String, String> = qs::from_str(path)?;
                creq.params = qs::to_string(params)?;
            }
        }

        let mut headers = BTreeSet::new();
        for (name, _) in req.headers() {
            headers.insert(CanonicalHeaderName(name.clone()));
        }
        creq.signed_headers = SignedHeaders { inner: headers };
        creq.headers = req.headers().clone();
        let payload = encode_with_hex(String::new());
        creq.payload_hash = payload;
        Ok(creq)
    }
}

impl TryFrom<&Request<String>> for CanonicalRequest {
    type Error = Error;
    fn try_from(req: &Request<String>) -> Result<Self, Self::Error> {
        let mut creq = CanonicalRequest::default();
        creq.method = req.method().clone();
        creq.path = req.uri().path_and_query().unwrap().path().to_string();

        if let Some(pq) = req.uri().path_and_query() {
            if let Some(path) = pq.query() {
                let params: BTreeMap<String, String> = qs::from_str(path)?;
                creq.params = qs::to_string(params)?;
            }
        }

        let mut headers = BTreeSet::new();
        for (name, _) in req.headers() {
            headers.insert(CanonicalHeaderName(name.clone()));
        }
        creq.signed_headers = SignedHeaders { inner: headers };
        creq.headers = req.headers().clone();
        let payload = encode_with_hex(req.body().to_string());
        creq.payload_hash = payload;
        Ok(creq)
    }
}

impl AsSigV4 for CanonicalRequest {
    fn fmt(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for CanonicalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(f, "{}", self.path)?;
        writeln!(f, "{}", self.params)?;
        // write out _all_ the headers
        for header in &self.signed_headers.inner {
            // a missing header is a bug, so we should panic.
            let value = &self.headers[&header.0];
            write!(f, "{}:", header.0.as_str())?;
            write!(f, "{}\n", value.to_str().unwrap())?;
        }
        write!(f, "\n")?;
        // write out the signed headers
        write!(f, "{}", self.signed_headers.to_string())?;
        write!(f, "\n")?;
        write!(f, "{}", self.payload_hash)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Default)]
pub(crate) struct SignedHeaders {
    inner: BTreeSet<CanonicalHeaderName>,
}

impl AsSigV4 for SignedHeaders {
    fn fmt(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for SignedHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.inner.iter().peekable();
        while let Some(next) = iter.next() {
            match iter.peek().is_some() {
                true => write!(f, "{};", next.0.as_str())?,
                false => write!(f, "{}", next.0.as_str())?,
            };
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct CanonicalHeaderName(HeaderName);

impl PartialOrd for CanonicalHeaderName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalHeaderName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_str().cmp(&other.0.as_str())
    }
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Scope {
    pub(crate) date: Date<Utc>,
    pub(crate) region: String,
    pub(crate) service: String,
}

impl<'a> AsSigV4 for Scope {
    fn fmt(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date.fmt_aws(),
            self.region,
            self.service
        )
    }
}

impl<'a> FromStr for Scope {
    type Err = Error;
    fn from_str(s: &str) -> Result<Scope, Self::Err> {
        let scopes = s
            .split("/")
            .map(|s| String::from(s))
            .collect::<Vec<String>>();
        let date = Date::<Utc>::parse_aws(&scopes[0])?;
        let region = &scopes[1];
        let service = &scopes[2];

        let scope = Scope {
            date,
            region: region.to_string(),
            service: service.to_string(),
        };

        Ok(scope)
    }
}

#[derive(PartialEq, Debug)]
pub(crate) struct StringToSign {
    pub(crate) scope: Scope,
    pub(crate) date: DateTime<Utc>,
    pub(crate) region: String,
    pub(crate) service: String,
    pub(crate) hashed_creq: String,
}

impl FromStr for StringToSign {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lines = s.lines().map(|s| String::from(s)).collect::<Vec<String>>();
        let date = DateTime::<Utc>::parse_aws(&lines[1])?;
        let scope: Scope = lines[2].parse()?;
        let hashed_creq = &lines[3];

        let sts = StringToSign {
            date,
            region: String::from(&scope.region),
            service: String::from(&scope.service),
            scope: scope.clone(),
            hashed_creq: hashed_creq.to_string(),
        };

        Ok(sts)
    }
}

impl StringToSign {
    pub(crate) fn new(date: DateTime<Utc>, region: &str, service: &str, hashed_creq: &str) -> Self {
        let scope = Scope {
            date: date.date(),
            region: region.to_string(),
            service: service.to_string(),
        };
        Self {
            scope,
            date,
            region: region.to_string(),
            service: service.to_string(),
            hashed_creq: hashed_creq.to_string(),
        }
    }
}

impl AsSigV4 for StringToSign {
    fn fmt(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}",
            HMAC_256,
            self.date.fmt_aws(),
            self.scope.fmt(),
            self.hashed_creq
        )
    }
}

pub(crate) trait DateTimeExt {
    // formats using SigV4's format. YYYYMMDD'T'HHMMSS'Z'.
    fn fmt_aws(&self) -> String;
    // YYYYMMDD
    fn parse_aws(s: &str) -> Result<DateTime<Utc>, ParseError>;
}

pub(crate) trait DateExt {
    fn fmt_aws(&self) -> String;

    fn parse_aws(s: &str) -> Result<Date<Utc>, ParseError>;
}

impl DateExt for Date<Utc> {
    fn fmt_aws(&self) -> String {
        self.format("%Y%m%d").to_string()
    }
    fn parse_aws(s: &str) -> Result<Date<Utc>, ParseError> {
        let date = NaiveDate::parse_from_str(s, "%Y%m%d")?;
        Ok(Date::<Utc>::from_utc(date, Utc))
    }
}

impl DateTimeExt for DateTime<Utc> {
    fn fmt_aws(&self) -> String {
        self.format(DATE_FORMAT).to_string()
    }

    fn parse_aws(s: &str) -> Result<DateTime<Utc>, ParseError> {
        let date = NaiveDateTime::parse_from_str(s, DATE_FORMAT)?;
        Ok(DateTime::<Utc>::from_utc(date, Utc))
    }
}
