use bytes::Bytes;
use chrono::{format::ParseError, prelude::*};
use eliza_error::Error;
use http::{
    header::HeaderName, uri::PathAndQuery, HeaderMap, HeaderValue, Method, Request, Uri, Version,
};
use ring::{
    digest::{self, digest, Digest},
    hmac::{self, Key},
};
use serde_urlencoded as qs;
use std::{
    cmp::{Ordering, PartialOrd},
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
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
    signed_headers: SignedHeaders,
    payload_hash: String,
}

#[derive(Debug, PartialEq, Default)]
struct SignedHeaders {
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

trait AsSigV4 {
    fn fmt(&self) -> String;
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

#[derive(PartialEq, Debug)]
struct Scope<'a> {
    date: Date<Utc>,
    region: &'a str,
    service: &'a str,
}

impl<'a> AsSigV4 for Scope<'a> {
    fn fmt(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date.fmt_aws(),
            self.region,
            self.service
        )
    }
}

#[derive(PartialEq, Debug)]
struct StringToSign<'a> {
    scope: Scope<'a>,
    date: DateTime<Utc>,
    region: &'a str,
    service: &'a str,
    hashed_creq: &'a str,
}

impl<'a> StringToSign<'a> {
    fn new(date: DateTime<Utc>, region: &'a str, service: &'a str, hashed_creq: &'a str) -> Self {
        let scope = Scope {
            date: date.date(),
            region,
            service,
        };
        Self {
            scope,
            date,
            region,
            service,
            hashed_creq,
        }
    }
}

impl<'a> AsSigV4 for StringToSign<'a> {
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
    let creq: CanonicalRequest = TryFrom::try_from(req)?;

    let actual = format!("{}", creq);
    let expected = fs::read_to_string("aws-sig-v4-test-suite/get-vanilla-query-order-key-case/get-vanilla-query-order-key-case.creq")?;
    assert_eq!(actual, expected);

    // Step 2: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-create-string-to-sign.html.
    let date = NaiveDateTime::parse_from_str("20150830T123600Z", DATE_FORMAT).unwrap();
    let date = DateTime::<Utc>::from_utc(date, Utc);
    let creq = &encode_with_hex(creq.fmt());
    let sts = StringToSign::new(date, "us-east-1", "iam", creq);

    // Step 3: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-calculate-signature.html
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    let signing_key = generate_signing_key(secret, date.date(), "us-east-1", "iam");
    let signature = calculate_signature(signing_key, &sts.fmt().as_bytes());

    // step 4: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-add-signature-to-request.html

    Ok(())
}

// add signature to authorization header
// Authorization: algorithm Credential=access key ID/credential scope, SignedHeaders=SignedHeaders, Signature=signature
fn build_authorization_header<'a>(
    access_key: &'a str,
    creq: CanonicalRequest,
    sts: StringToSign<'a>,
    signature: &'a str,
) -> String {
    format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        HMAC_256,
        access_key,
        sts.scope.fmt(),
        creq.signed_headers,
        signature
    )
}

#[test]
fn test_build_authorization_header() -> Result<(), Error> {
    let s = fs::read_to_string(
        "aws-sig-v4-test-suite/get-vanilla-query-order-key-case/get-vanilla-query-order-key-case.req",
    )?;
    let req = parse_request(s)?;
    let creq: CanonicalRequest = TryFrom::try_from(req)?;

    let date = NaiveDateTime::parse_from_str("20150830T123600Z", DATE_FORMAT).unwrap();
    let date = DateTime::<Utc>::from_utc(date, Utc);
    let encoded_creq = &encode_with_hex(creq.fmt());
    let sts = StringToSign::new(date, "us-east-1", "service", encoded_creq);

    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let signing_key = generate_signing_key(secret, date.date(), "us-east-1", "service");
    let signature = calculate_signature(signing_key, &sts.fmt().as_bytes());
    let expected_header = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500";
    let access_key = "AKIDEXAMPLE";

    let header = build_authorization_header(access_key, creq, sts, &signature);
    assert_eq!(expected_header, header);

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
    let encoded = encode_with_hex(creq);

    let actual = StringToSign::new(date, "us-east-1", "service", &encoded);
    assert_eq!(expected_sts, actual.fmt());

    Ok(())
}

#[test]
fn test_signature_calculation() -> Result<(), Error> {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let creq = fs::read_to_string(format!("aws-sig-v4-test-suite/iam.creq"))?;
    let date = DateTime::parse_aws("20150830T123600Z")?;

    let derived_key = generate_signing_key(secret, date.date(), "us-east-1", "iam");
    let signature = calculate_signature(derived_key, creq.as_bytes());

    let expected = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
    assert_eq!(expected, &signature);

    Ok(())
}

#[test]
fn test_generate_scope() -> Result<(), Error> {
    let expected = "20150830/us-east-1/iam/aws4_request\n";
    let date = DateTime::parse_aws("20150830T123600Z")?;
    let scope = Scope {
        date: date.date(),
        region: "us-east-1",
        service: "iam",
    };
    assert_eq!(format!("{}\n", scope.fmt()), expected);

    Ok(())
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

// HMAC
fn encode(s: String) -> Vec<u8> {
    let calculated = digest::digest(&digest::SHA256, s.as_bytes());
    calculated.as_ref().to_vec()
}

/// HashedPayload = Lowercase(HexEncode(Hash(requestPayload)))
fn encode_with_hex(s: String) -> String {
    let digest: Digest = digest::digest(&digest::SHA256, s.as_bytes());
    // no need to lower-case as in step six, as hex::encode
    // already returns a lower-cased string.
    hex::encode(digest)
}

fn calculate_signature(signing_key: hmac::Tag, string_to_sign: &[u8]) -> String {
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, signing_key.as_ref());
    let tag = hmac::sign(&s_key, string_to_sign);

    hex::encode(tag)
}

// kSecret = your secret access key
// kDate = HMAC("AWS4" + kSecret, Date)
// kRegion = HMAC(kDate, Region)
// kService = HMAC(kRegion, Service)
// kSigning = HMAC(kService, "aws4_request")
fn generate_signing_key(secret: &str, date: Date<Utc>, region: &str, service: &str) -> hmac::Tag {
    let secret = format!("AWS4{}", secret);
    let secret = hmac::Key::new(hmac::HMAC_SHA256, &secret.as_bytes());
    let tag = hmac::sign(&secret, date.fmt_aws().as_bytes());

    // sign region
    let key = hmac::Key::new(hmac::HMAC_SHA256, tag.as_ref());
    let tag = hmac::sign(&key, region.as_bytes());

    // sign service
    let key = hmac::Key::new(hmac::HMAC_SHA256, tag.as_ref());
    let tag = hmac::sign(&key, service.as_bytes());

    // sign request
    let key = hmac::Key::new(hmac::HMAC_SHA256, tag.as_ref());
    hmac::sign(&key, "aws4_request".as_bytes())
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
