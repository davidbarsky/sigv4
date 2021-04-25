use aws_sigv4::{sign, Credentials};
use bytes::Bytes;
use http::{header, Method, Request, Uri, Version};
use http_body::Body as _;
use hyper::{Body, Client};

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let https = hyper_tls::HttpsConnector::new();
    let client: Client<_, hyper::Body> = Client::builder().build(https);

    let uri =
        Uri::from_static("https://ec2.amazonaws.com/?Action=DescribeRegions&Version=2013-10-15");
    let builder = Request::builder();
    let mut builder = builder
        .method(Method::POST)
        .uri(uri)
        .version(Version::HTTP_11);
    let headers = builder.headers_mut().expect("Missing headers");
    headers.insert(header::HOST, "ec2.amazonaws.com".parse()?);

    let mut req = builder.body(Bytes::new())?;
    let access = std::env::var("AWS_ACCESS_KEY_ID")?;
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY")?;
    let credentials = Credentials {
        access_key: &access,
        secret_key: &secret,
        security_token: None,
    };

    sign(&mut req, &credentials, "us-east-1", "ec2")?;
    let req = reconstruct(req);
    let mut res = client.request(req).await?;
    let mut body = vec![];
    while let Some(Ok(chunk)) = res.body_mut().data().await {
        body.extend_from_slice(&chunk);
    }
    println!("{:?}", body);

    Ok(())
}

fn reconstruct(req: Request<Bytes>) -> Request<Body> {
    let (headers, body) = req.into_parts();
    let body = Body::from(body);
    Request::from_parts(headers, body)
}
