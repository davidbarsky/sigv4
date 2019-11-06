use bytes::Bytes;
use eliza_error::Error;
use futures::stream::TryStreamExt;
use http::{
    header::{CONTENT_TYPE, HOST},
    HttpTryFrom, Method, Request, Response, Uri, Version,
};
use hyper::{client::HttpConnector, Body, Client};
use hyper_rustls::HttpsConnector;
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

trait IntoRequest {
    fn into_request(self, region: Region) -> Result<Request<Bytes>, Error>;
}

#[derive(Debug, PartialEq)]
struct CreateTableRequest {
    table_name: String,
}

impl IntoRequest for CreateTableRequest {
    fn into_request(self, region: Region) -> Result<Request<Bytes>, Error> {
        let uri = format!("https://dynamodb.{}.amazonaws.com/", region.inner);
        let host = format!("dynamodb.{}.amazonaws.com", region.inner);
        let uri = Uri::try_from(uri)?;

        let mut builder = Request::builder();
        builder
            .method(Method::POST)
            .uri(uri)
            .version(Version::HTTP_11);
        let headers = builder.headers_mut().expect("Missing headers");
        headers.insert(CONTENT_TYPE, "application/x-amz-json-1.0".parse()?);
        headers.insert(HOST, host.parse()?);
        headers.insert(X_AMZ_TARGET, "DynamoDB_20120810.CreateTable".parse()?);

        let params = json!({
            "KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],
            "TableName": self.table_name,
            "AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],
            "ProvisionedThroughput": {"WriteCapacityUnits": 1,"ReadCapacityUnits": 1}
        });
        let params = serde_json::to_vec(&params)?;

        let mut req = builder.body(Bytes::from(params))?;
        req.set_service(Service::new("dynamodb"));
        req.set_region(region);
        Ok(req)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = AWSClient::new();

    let req = CreateTableRequest {
        table_name: "example_table".to_string(),
    };
    let res = client.call(req).await?;

    let body = res.into_body().try_concat().await?;
    let response = serde_json::from_slice::<serde_json::Value>(&body)?;
    println!("{}", response);

    Ok(())
}

struct AWSClient {
    inner: Client<HttpsConnector<HttpConnector>, Body>,
}

impl AWSClient {
    fn new() -> Self {
        let https = hyper_rustls::HttpsConnector::new();
        let inner: Client<_, hyper::Body> = Client::builder().build(https);
        Self { inner }
    }

    async fn call<T: IntoRequest>(&self, req: T) -> Result<Response<Body>, Error> {
        let credentials = load_credentials()?;
        let signed = reconstruct(sign(
            req.into_request(Region { inner: "us-east-1" })?,
            credentials,
        )?);
        let res = self.inner.request(signed).await?;
        Ok(res)
    }
}

fn reconstruct(req: Request<Bytes>) -> Request<Body> {
    let (headers, body) = req.into_parts();
    let body = Body::from(body);
    Request::from_parts(headers, body)
}
