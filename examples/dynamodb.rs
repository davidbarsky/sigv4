use eliza_error::Error;
use futures::stream::TryStreamExt;
use http::{header, Method, Request, Uri, Version};
use hyper::{Body, Client};
use serde_json::json;
use std::env;

use sigv4::{sign, Credentials, Region, RequestExt, Service};

const X_AMZ_TARGET: &'static str = "x-amz-target";

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
    headers.insert(header::CONTENT_TYPE, "application/x-amz-json-1.0".parse()?);
    headers.insert(header::HOST, "dynamodb.us-east-1.amazonaws.com".parse()?);
    headers.insert(X_AMZ_TARGET, "DynamoDB_20120810.CreateTable".parse()?);

    let params = json!({
        "KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],
        "TableName": "TestTable",
        "AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],
        "ProvisionedThroughput": {"WriteCapacityUnits": 1,"ReadCapacityUnits": 1}
    });
    let params = serde_json::to_string(&params)?;
    let mut req = builder.body(params)?;

    let access = env::var("AWS_ACCESS_KEY")?;
    let secret = env::var("AWS_SECRET_KEY")?;

    req.set_service(Service::new("dynamodb"));
    req.set_region(Region::new("us-east-1"));
    req.set_credential(Credentials::new(access, secret));

    let signed = reconstruct(sign(req)?);
    let res = client.request(signed).await?;
    let (headers, body) = res.into_parts();
    println!("{:?}", headers);
    let body = body.try_concat().await?;
    let tables = serde_json::from_slice::<serde_json::Value>(&body)?;
    println!("{}", tables);

    Ok(())
}

fn reconstruct(req: Request<String>) -> Request<Body> {
    let (headers, body) = req.into_parts();
    let body = Body::from(body);
    Request::from_parts(headers, body)
}
