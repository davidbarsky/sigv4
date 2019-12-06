use bytes::Bytes;
use eliza_error::Error;
use http::{
    header::{CONTENT_TYPE, HOST},
    Method, Request, Response, Uri, Version,
};
use http_body::Body as _;
use hyper::{client::HttpConnector, Body, Client};
use serde_json::json;
use std::convert::TryFrom;

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
    let region = Region { inner: "us-east-1" };
    let client = AWSClient::new(region);

    let req = DescribeTableRequest {
        table_name: "Table",
    };
    let res = client.call(req).await?;
    read_response(res).await?;

    let id = "6da57b8d-e199-490d-9803-13bb35bdf19c";
    let req = PutItemRequest {
        table_name: "Table",
        consistent_read: true,
        item: json!({
           "Id": {
               "S": id
            },
            "Message": {
                "S": "hello, world!"
            }
        }),
    };
    let res = client.call(req).await?;
    read_response(res).await?;

    let id = "6da57b8d-e199-490d-9803-13bb35bdf19c";
    let req = GetItemRequest {
        table_name: "Table",
        consistent_read: true,
        key: json!({
           "Id": {
               "S": id
            }
        }),
    };
    let res = client.call(req).await?;
    read_response(res).await?;

    Ok(())
}

async fn read_response(res: Response<Body>) -> Result<(), Error> {
    let mut res = res;
    let mut body = vec![];
    while let Some(Ok(chunk)) = res.body_mut().data().await {
        body.extend_from_slice(&chunk);
    }
    let response = serde_json::from_slice::<serde_json::Value>(&body)?;
    println!("{:?}", response);
    Ok(())
}

trait IntoRequest {
    const OPERATION_NAME: &'static str;
    fn params(self) -> serde_json::Value
    where
        Self: Sized;

    fn into_request(self, region: Region) -> Result<Request<Bytes>, Error>
    where
        Self: Sized,
    {
        let uri = format!("https://dynamodb.{}.amazonaws.com/", region.inner);
        let host = format!("dynamodb.{}.amazonaws.com", region.inner);
        let uri = Uri::try_from(uri)?;
        let operation_name = format!("DynamoDB_20120810.{}", Self::OPERATION_NAME);

        let builder = Request::builder();
        let mut builder = builder
            .method(Method::POST)
            .uri(uri)
            .version(Version::HTTP_11);
        let headers = builder.headers_mut().expect("Missing headers");
        headers.insert(CONTENT_TYPE, "application/x-amz-json-1.0".parse()?);
        headers.insert(HOST, host.parse()?);
        headers.insert(X_AMZ_TARGET, operation_name.parse()?);

        let params = serde_json::to_vec(&self.params())?;
        let mut req = builder.body(Bytes::from(params))?;
        req.set_service(Service::new("dynamodb"));
        req.set_region(region);
        Ok(req)
    }
}

#[derive(Debug, PartialEq)]
struct CreateTableRequest {
    table_name: &'static str,
}

impl IntoRequest for CreateTableRequest {
    const OPERATION_NAME: &'static str = "CreateTable";
    fn params(self) -> serde_json::Value
    where
        Self: Sized,
    {
        json!({
            "KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],
            "TableName": self.table_name,
            "AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],
            "ProvisionedThroughput": {"WriteCapacityUnits": 1,"ReadCapacityUnits": 1}
        })
    }
}

struct DescribeTableRequest {
    table_name: &'static str,
}

impl IntoRequest for DescribeTableRequest {
    const OPERATION_NAME: &'static str = "DescribeTable";
    fn params(self) -> serde_json::Value
    where
        Self: Sized,
    {
        json!({
            "TableName": self.table_name,
        })
    }
}

struct DeleteTableRequest {
    table_name: &'static str,
}

impl IntoRequest for DeleteTableRequest {
    const OPERATION_NAME: &'static str = "DeleteTable";
    fn params(self) -> serde_json::Value
    where
        Self: Sized,
    {
        json!({
            "TableName": self.table_name,
        })
    }
}

#[derive(Debug, PartialEq, Default)]
struct GetItemRequest {
    table_name: &'static str,
    key: serde_json::Value,
    consistent_read: bool,
}

impl IntoRequest for GetItemRequest {
    const OPERATION_NAME: &'static str = "GetItem";
    fn params(self) -> serde_json::Value
    where
        Self: Sized,
    {
        json!({
            "TableName": self.table_name,
            "Key": self.key,
            "ConsistentRead": self.consistent_read,
        })
    }
}

#[derive(Debug, PartialEq, Default)]
struct PutItemRequest {
    table_name: &'static str,
    item: serde_json::Value,
    consistent_read: bool,
}

impl IntoRequest for PutItemRequest {
    const OPERATION_NAME: &'static str = "PutItem";
    fn params(self) -> serde_json::Value
    where
        Self: Sized,
    {
        json!({
            "TableName": self.table_name,
            "Item": self.item,
            "ConsistentRead": self.consistent_read,
        })
    }
}

struct AWSClient {
    inner: Client<hyper_tls::HttpsConnector<HttpConnector>, Body>,
    region: &'static str,
}

impl AWSClient {
    fn new(region: Region) -> Self {
        let https = hyper_tls::HttpsConnector::new().unwrap();
        let inner: Client<_, hyper::Body> = Client::builder().build(https);
        Self {
            inner,
            region: region.inner,
        }
    }

    async fn call<T: IntoRequest>(&self, req: T) -> Result<Response<Body>, Error> {
        let credentials = load_credentials()?;
        let signed = reconstruct(sign(
            req.into_request(Region { inner: self.region })?,
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
