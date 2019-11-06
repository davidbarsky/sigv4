use bytes::Bytes;
use eliza_error::Error;
use futures::stream::TryStreamExt;
use http::{header, Method, Request, Uri, Version};
use hyper::{Body, Client};

use sigv4::{sign, Credentials, Region, RequestExt, Service};

fn load_credentials() -> Result<Credentials, Error> {
    let access = std::env::var("AWS_ACCESS_KEY_ID")?;
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY")?;

    Ok(Credentials {
        access_key: access,
        secret_key: secret,
        ..Default::default()
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let https = hyper_rustls::HttpsConnector::new();
    let client: Client<_, hyper::Body> = Client::builder().build(https);

    let uri =
        Uri::from_static("https://ec2.amazonaws.com/?Action=DescribeRegions&Version=2013-10-15");
    let mut builder = Request::builder();
    builder
        .method(Method::POST)
        .uri(uri)
        .version(Version::HTTP_11);
    let headers = builder.headers_mut().expect("Missing headers");
    headers.insert(header::HOST, "ec2.amazonaws.com".parse()?);

    let mut req = builder.body(Bytes::new())?;
    req.set_service(Service::new("ec2"));
    req.set_region(Region::new("us-east-1"));
    let credentials = load_credentials()?;

    let signed = reconstruct(sign(req, credentials)?);
    let res = client.request(signed).await?;
    let (headers, body) = res.into_parts();
    println!("{:?}", headers);
    let body = body.try_concat().await?;
    let body = Bytes::from(body);
    println!("{:?}", body);

    Ok(())
}

fn reconstruct(req: Request<Bytes>) -> Request<Body> {
    let (headers, body) = req.into_parts();
    let body = Body::from(body);
    Request::from_parts(headers, body)
}
