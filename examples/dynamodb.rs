use bytes::Bytes;
use eliza_error::Error;
use futures::stream::TryStreamExt;
use http::{
    header::{CONTENT_TYPE, HOST},
    Method, Request, Uri, Version,
};
use hyper::{Body, Client};
use serde_json::json;

use sigv4::{sign, Credentials, Region, RequestExt, Service, X_AMZ_TARGET};

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

    let uri = Uri::from_static("https://dynamodb.us-east-1.amazonaws.com/");
    let mut builder = Request::builder();
    builder
        .method(Method::POST)
        .uri(uri)
        .version(Version::HTTP_11);
    let headers = builder.headers_mut().expect("Missing headers");
    headers.insert(CONTENT_TYPE, "application/x-amz-json-1.0".parse()?);
    headers.insert(HOST, "dynamodb.us-east-1.amazonaws.com".parse()?);
    headers.insert(X_AMZ_TARGET, "DynamoDB_20120810.CreateTable".parse()?);

    let params = json!({
        "KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],
        "TableName": "TestTable",
        "AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],
        "ProvisionedThroughput": {"WriteCapacityUnits": 1,"ReadCapacityUnits": 1}
    });
    let params = serde_json::to_vec(&params)?;
    let mut req = builder.body(Bytes::from(params))?;

    req.set_service(Service::new("dynamodb"));
    req.set_region(Region::new("us-east-1"));
    let credentials = load_credentials()?;

    let signed = reconstruct(sign(req, credentials)?);
    let res = client.request(signed).await?;
    let (headers, body) = res.into_parts();
    println!("{:?}", headers);
    let body = body.try_concat().await?;
    let tables = serde_json::from_slice::<serde_json::Value>(&body)?;
    println!("{}", tables);

    Ok(())
}

fn reconstruct(req: Request<Bytes>) -> Request<Body> {
    let (headers, body) = req.into_parts();
    let body = Body::from(body);
    Request::from_parts(headers, body)
}
