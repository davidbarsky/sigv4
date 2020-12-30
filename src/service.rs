use crate::{sign, Credentials};
use http::Request;
use std::task;
use tower::{layer::Layer, Service};

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

impl<T, B> Service<Request<B>> for SignAndPrepare<T>
where
    T: Service<Request<hyper::Body>>,
    B: AsRef<[u8]>,
{
    type Response = T::Response;
    type Error = T::Error;
    type Future = T::Future;

    fn poll_ready(&mut self, cx: &mut task::Context) -> task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let region = req.get_region().expect("Missing region, this is a bug.");
        let svc = req.get_service().expect("Missing service, this is a bug.");
        let mut req = req;
        sign(&mut req, &self.credentials, &region, &svc).unwrap();
        let req = map_body(req);
        // Call the inner service
        self.inner.call(req)
    }
}

fn map_body<B>(req: Request<B>) -> Request<hyper::Body>
where
    B: AsRef<[u8]>,
{
    let (headers, body) = req.into_parts();
    let body = hyper::Body::from(body.as_ref().to_vec());
    Request::from_parts(headers, body)
}
