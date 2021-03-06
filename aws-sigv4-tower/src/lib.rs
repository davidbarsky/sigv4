use aws_sigv4::{sign, Credentials};
use std::task;
use tower::{layer::Layer, Service};

pub struct Request<'a, B> {
    pub inner: http::Request<B>,
    pub region: &'a str,
    pub service: &'a str,
}

pub struct SignAndPrepare<S> {
    inner: S,
    pub credentials: Credentials,
}

pub struct SignAndPrepareLayer {
    pub credentials: Credentials,
}

impl<S> Layer<S> for SignAndPrepareLayer {
    type Service = SignAndPrepare<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignAndPrepare {
            inner,
            credentials: self.credentials.clone(),
        }
    }
}

impl<'a, T, B> Service<Request<'a, B>> for SignAndPrepare<T>
where
    T: Service<http::Request<hyper::Body>>,
    B: AsRef<[u8]>,
{
    type Response = T::Response;
    type Error = T::Error;
    type Future = T::Future;

    fn poll_ready(&mut self, cx: &mut task::Context) -> task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<'a, B>) -> Self::Future {
        let Request {
            inner,
            region,
            service,
        } = req;

        let mut req: http::Request<B> = inner;
        sign(&mut req, &self.credentials, &region, &service).unwrap();

        let req = map_body(req);

        // Call the inner service
        self.inner.call(req)
    }
}

fn map_body<B>(req: http::Request<B>) -> http::Request<hyper::Body>
where
    B: AsRef<[u8]>,
{
    let (headers, body) = req.into_parts();
    let body = hyper::Body::from(body.as_ref().to_vec());
    http::Request::from_parts(headers, body)
}
