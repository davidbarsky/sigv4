use bytes::Bytes;
use chrono::{format::ParseError, prelude::*};
use eliza_error::Error;
use hmac::{Hmac, Mac};
use http::{
    header::HeaderName, uri::PathAndQuery, HeaderMap, HeaderValue, Method, Request, Uri, Version,
};
use ring::{
    digest::{self, digest, Digest as RingDigest},
    hmac::{self as ringhmac, Key},
};
use serde_urlencoded as qs;
use sha2::{Digest, Sha256};
use std::{
    cmp::{Ordering, PartialOrd},
    collections::{BTreeMap, BTreeSet},
    error::Error as _,
    fmt, fs, str,
};

#[cfg(test)]
use pretty_assertions::assert_eq;

const HMAC_256: &'static str = "AWS4-HMAC-SHA256";
const DATE_FORMAT: &'static str = "%Y%m%dT%H%M%SZ";

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
        write!(f, "\n")?;
        // write out the signed headers
        let mut iter = self.signed_headers.iter().peekable();
        while let Some(next) = iter.next() {
            match iter.peek().is_some() {
                true => write!(f, "{};", next.0.as_str())?,
                false => write!(f, "{}", next.0.as_str())?,
            };
        }
        write!(f, "\n")?;
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

trait DateTimeExt {
    // formats using SigV4's format. YYYYMMDD'T'HHMMSS'Z'.
    fn fmt_aws(&self) -> String;
    // YYYYMMDD
    fn parse_aws(s: &str) -> Result<DateTime<Utc>, ParseError>;
}

trait DateExt {
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

#[test]
fn read_request() -> Result<(), Error> {
    //file-name.req—the web request to be signed.
    //file-name.creq—the resulting canonical request.
    //file-name.sts—the resulting string to sign.
    //file-name.authz—the Authorization header.
    //file-name.sreq— the signed request.

    // Step 1: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-create-canonical-request.html.
    let s = fs::read_to_string(
        "aws-sig-v4-test-suite/get-vanilla-query-order-key-case/get-vanilla-query-order-key-case.req",
    )?;
    let req = parse_request(s)?;
    let mut creq = CanonicalRequest::default();
    creq.method = req.method().clone();
    creq.path = req.uri().path_and_query().unwrap().path().to_string();

    if let Some(pq) = req.uri().path_and_query() {
        if let Some(path) = pq.query() {
            let params: BTreeMap<String, String> = qs::from_str(path).unwrap();
            creq.params = qs::to_string(params)?;
        }
    }

    let mut headers = BTreeSet::new();
    for (name, _) in req.headers() {
        headers.insert(CanonicalHeaderName(name.clone()));
    }
    creq.signed_headers = headers;
    creq.headers = req.headers().clone();
    let payload = encode_with_hex(String::new());
    creq.payload_hash = payload;

    let actual = format!("{}", creq);
    let expected = fs::read_to_string("aws-sig-v4-test-suite/get-vanilla-query-order-key-case/get-vanilla-query-order-key-case.creq")?;
    assert_eq!(actual, expected);

    // Step 2: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-create-string-to-sign.html.
    let date = NaiveDateTime::parse_from_str("20150830T123600Z", DATE_FORMAT).unwrap();
    let date = DateTime::<Utc>::from_utc(date, Utc);
    let string_to_sign =
        string_to_sign(date, "us-east-1", "iam", &encode_with_hex(creq.to_string()));

    // Step 3: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-calculate-signature.html
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    let signing_key = generate_signing_key_2(secret, date.date(), "us-east-1", "iam");
    let signing_key_2 = generate_signing_key_3(secret, date.date(), "us-east-1", "iam");

    let signature = calculate_signature(signing_key, &string_to_sign.as_bytes());
    let signature_2 = calculate_signature_2(&signing_key_2, string_to_sign.as_bytes());

    dbg!(signature);
    dbg!(signature_2);

    Ok(())
}

#[test]
fn sign_payload_empty_string() {
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let actual = encode_with_hex(String::new());
    assert_eq!(expected, actual);
}

#[test]
fn datetime_format() -> Result<(), Error> {
    let date = DateTime::parse_aws("20150830T123600Z")?;
    let expected = "20150830T123600Z";
    assert_eq!(expected, date.fmt_aws());

    Ok(())
}

#[test]
fn date_format() -> Result<(), Error> {
    let date = Date::parse_aws("20150830")?;
    let expected = "20150830";
    assert_eq!(expected, date.fmt_aws());

    Ok(())
}

#[test]
fn test_string_to_sign() -> Result<(), Error> {
    let date = DateTime::parse_aws("20150830T123600Z")?;
    let case = "get-vanilla-query-order-key-case";
    let creq = fs::read_to_string(format!("aws-sig-v4-test-suite/{}/{}.creq", case, case))?;

    let expected_sts = fs::read_to_string(format!("aws-sig-v4-test-suite/{}/{}.sts", case, case))?;
    let encoded = encode_with_hex(creq.to_string());

    let actual = string_to_sign(date, "us-east-1", "service", &encoded);
    assert_eq!(expected_sts, actual);

    Ok(())
}

#[test]
fn test_signature_calculation() -> Result<(), Error> {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let creq = fs::read_to_string(format!("aws-sig-v4-test-suite/iam.creq"))?;
    let date = DateTime::parse_aws("20150830T123600Z")?;

    let derived_key = generate_signing_key_2(secret, date.date(), "us-east-1", "iam");
    let actual = calculate_signature(derived_key, creq.as_bytes());

    let expected_signature = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
    assert_eq!(expected_signature, &actual);

    Ok(())
}

#[test]
fn test_generate_scope() -> Result<(), Error> {
    let date = DateTime::parse_aws("20150830T123600Z")?;
    let expected = "20150830/us-east-1/iam/aws4_request\n";
    let actual = generate_scope(date, "us-east-1", "iam");
    assert_eq!(expected, actual);

    Ok(())
}

#[inline]
fn hmac(secret: &[u8], message: &[u8]) -> Hmac<Sha256> {
    let mut hmac = Hmac::<Sha256>::new_varkey(secret).expect("failed to create hmac");
    hmac.input(message);
    hmac
}

#[test]
fn test_digest_of_canonical_request() -> Result<(), Error> {
    let case = "get-vanilla-query-order-key-case";
    let creq = fs::read_to_string(format!("aws-sig-v4-test-suite/{}/{}.creq", case, case))?;
    let actual = encode_with_hex(creq);
    let expected = "816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0";

    assert_eq!(expected, actual);
    Ok(())
}

fn generate_scope(date: DateTime<Utc>, region: &str, service: &str) -> String {
    format!(
        "{}/{}/{}/aws4_request\n",
        date.date().fmt_aws(),
        region,
        service
    )
}

fn string_to_sign(date: DateTime<Utc>, region: &str, service: &str, hashed_creq: &str) -> String {
    let scope = generate_scope(date, region, service);
    format!("{}\n{}\n{}{}", HMAC_256, date.fmt_aws(), scope, hashed_creq)
}

// HMAC
fn encode(s: String) -> Vec<u8> {
    let calculated = digest::digest(&digest::SHA256, s.as_bytes());
    calculated.as_ref().to_vec()
}

/// HashedPayload = Lowercase(HexEncode(Hash(requestPayload)))
fn encode_with_hex(s: String) -> String {
    let digest: RingDigest = digest::digest(&digest::SHA256, s.as_bytes());
    // no need to lower-case as in step six, as hex::encode
    // already returns a lower-cased string.
    hex::encode(digest)
}

fn calculate_signature(signing_key: ringhmac::Tag, string_to_sign: &[u8]) -> String {
    let s_key = ringhmac::Key::new(ringhmac::HMAC_SHA256, signing_key.as_ref());
    let tag = ringhmac::sign(&s_key, string_to_sign);

    hex::encode(tag)
}

// kSecret = your secret access key
// kDate = HMAC("AWS4" + kSecret, Date)
// kRegion = HMAC(kDate, Region)
// kService = HMAC(kRegion, Service)
// kSigning = HMAC(kService, "aws4_request")
fn generate_signing_key_2(
    secret: &str,
    date: Date<Utc>,
    region: &str,
    service: &str,
) -> ringhmac::Tag {
    let secret = format!("AWS4{}", secret);
    let secret = ringhmac::Key::new(ringhmac::HMAC_SHA256, &secret.as_bytes());
    let tag = ringhmac::sign(&secret, date.fmt_aws().as_bytes());

    // sign region
    let key = ringhmac::Key::new(ringhmac::HMAC_SHA256, tag.as_ref());
    let tag = ringhmac::sign(&key, region.as_bytes());

    // sign service
    let key = ringhmac::Key::new(ringhmac::HMAC_SHA256, tag.as_ref());
    let tag = ringhmac::sign(&key, service.as_bytes());

    // sign request
    let key = ringhmac::Key::new(ringhmac::HMAC_SHA256, tag.as_ref());
    ringhmac::sign(&key, "aws4_request".as_bytes())
}

fn generate_signing_key_3<'a>(
    secret: &str,
    date: Date<Utc>,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let secret = format!("AWS4{}", secret);
    let secret = secret.as_bytes();
    let date = date.fmt_aws();
    let date = date.as_bytes();
    let date = hmac(secret, date).result().code();

    let region = region.as_bytes();
    let region = hmac(&date, region).result().code();

    let service = service.as_bytes();
    let service = hmac(&region, service).result().code();

    hmac(&service, b"aws4_request").result().code().to_vec()
}

// signature = HexEncode(HMAC(derived signing key, string to sign))
fn calculate_signature_2(derived_key: &[u8], string_to_sign: &[u8]) -> String {
    let hmac = hmac(derived_key, string_to_sign).result().code();
    hex::encode(hmac)
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
