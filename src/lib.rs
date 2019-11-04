use bytes::Bytes;
use chrono::prelude::*;
use eliza_error::Error;
use http::{
    header::HeaderName, uri::PathAndQuery, HeaderMap, HeaderValue, Method, Request, Uri, Version,
};
use ring::digest::{self, digest, Digest};
use serde_urlencoded as qs;
use std::{
    cmp::{Ordering, PartialOrd},
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
};

#[cfg(test)]
use pretty_assertions::assert_eq;

const HMAC_256: &'static str = "AWS4-HMAC-SHA256";

#[derive(Default, Debug, PartialEq)]
struct CanonicalRequest {
    method: Method,
    path: String,
    params: String,
    headers: HeaderMap,
    signed_headers: BTreeSet<CanonicalHeaderName>,
    payload_hash: String,
}

impl fmt::Display for CanonicalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(f, "{}", self.path)?;
        writeln!(f, "{}", self.params)?;
        // write out _all_ the headers
        for header in &self.signed_headers {
            // a missing header is a bug, so we should panic.
            let value = &self.headers[&header.0];
            write!(f, "{}:", header.0.as_str())?;
            write!(f, "{}\n", value.to_str().unwrap())?;
        }
        write!(f, "\n");
        // write out the signed headers
        let mut iter = self.signed_headers.iter().peekable();
        while let Some(next) = iter.next() {
            match iter.peek().is_some() {
                true => write!(f, "{};", next.0.as_str()),
                false => write!(f, "{}", next.0.as_str()),
            }?;
        }
        write!(f, "\n");
        write!(f, "{}", self.payload_hash)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct CanonicalHeaderName(HeaderName);

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

#[test]
fn read_request() -> Result<(), Error> {
    //file-name.req—the web request to be signed.
    //file-name.creq—the resulting canonical request.
    //file-name.sts—the resulting string to sign.
    //file-name.authz—the Authorization header.
    //file-name.sreq— the signed request.

    let s = fs::read_to_string(
        "aws-sig-v4-test-suite/get-vanilla-query-order-key-case/get-vanilla-query-order-key-case.req",
    )?;
    let req = parse_request(s)?;
    let mut canonical_request = CanonicalRequest::default();
    canonical_request.method = req.method().clone();
    canonical_request.path = req.uri().path_and_query().unwrap().path().to_string();

    if let Some(pq) = req.uri().path_and_query() {
        if let Some(path) = pq.query() {
            let params: BTreeMap<String, String> = qs::from_str(path).unwrap();
            canonical_request.params = qs::to_string(params)?;
        }
    }

    let mut headers = BTreeSet::new();
    for (name, _) in req.headers() {
        headers.insert(CanonicalHeaderName(name.clone()));
    }
    canonical_request.signed_headers = headers;
    canonical_request.headers = req.headers().clone();
    let payload = sign_payload(String::new());
    canonical_request.payload_hash = payload;

    let actual = format!("{}", canonical_request);
    let expected = fs::read_to_string("aws-sig-v4-test-suite/get-vanilla-query-order-key-case/get-vanilla-query-order-key-case.creq")?;
    assert_eq!(actual, expected);
    string_to_sign(Utc::now());

    Ok(())
}

#[test]
fn sign_payload_empty_string() {
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let actual = sign_payload(String::new());
    assert_eq!(expected, actual);
}

fn string_to_sign(date: DateTime<Utc>) -> String {
    let date = date.format("YYYYMMDDHHMMSSZ");
    let date = format!("{}", date);
    dbg!(&date);
    let credential_scope = String::new();
    let hashed_canonical_request = String::new();
    format!("{}\n{}\n{}\n", HMAC_256, date, credential_scope)
}

/// HashedPayload = Lowercase(HexEncode(Hash(requestPayload)))
fn sign_payload(s: String) -> String {
    let digest: Digest = digest::digest(&digest::SHA256, s.as_bytes());
    // no need to lower-case as in step six, as hex::encode
    // already returns a lower-cased string.
    hex::encode(digest)
}

fn parse_request(s: String) -> Result<Request<()>, Error> {
    let mut req = Request::builder();
    let mut lines = s.lines();

    // handle protocol
    let protocol = lines.next().unwrap();
    let protocol = protocol.split(" ").collect::<Vec<&str>>();
    req.method(protocol[0]);
    let pq = PathAndQuery::from_shared(Bytes::from(protocol[1]))?;
    let version = match protocol[2] {
        "HTTP/1.1" => Version::HTTP_11,
        "HTTP/2.0" => Version::HTTP_2,
        _ => unimplemented!(),
    };
    req.version(version);

    for h in lines {
        let split = h.split(":").collect::<Vec<&str>>();
        req.header(split[0], split[1]);
        if split[0] == http::header::HOST {
            let uri = Uri::builder()
                .scheme("https")
                .authority(split[1])
                .path_and_query(pq.clone())
                .build()?;
            req.uri(uri);
        }
    }
    let req = req.body(())?;
    Ok(req)
}
