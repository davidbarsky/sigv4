use tower::{Service, layer::Layer};
use http::Request;
use std::task;
use crate::{Credentials, sign};

pub struct Sign<S> {
    inner: S,
    pub credentials: Credentials,
}

pub struct SignLayer {
    pub credentials: Credentials
}

impl<S> Layer<S> for SignLayer {
    type Service = Sign<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Sign {
            inner,
            credentials: self.credentials.clone()
        }
    }
}

impl<T, B> Service<Request<B>> for Sign<T>
where
    T: Service<Request<B>>,
    B: AsRef<[u8]>,
{
    type Response = T::Response;
    type Error = T::Error;
    type Future = T::Future;

    fn poll_ready(&mut self, cx: &mut task::Context) -> task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut req = req;
        sign(&mut req, &self.credentials).unwrap();
        // Call the inner service
        self.inner.call(req)
    }
}

pub struct ConvertBodyLayer;

impl<S> Layer<S> for ConvertBodyLayer {
    type Service = ConvertBody<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConvertBody {
            inner
        }
    }
}

pub struct ConvertBody<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for ConvertBody<S>
where
    S: Service<Request<hyper::Body>>,
    B: AsRef<[u8]>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;
    
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> { 
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future { 
        let (headers, body) = req.into_parts();
        let body = hyper::Body::from(body.as_ref().to_vec());
        let req = Request::from_parts(headers, body);

        self.inner.call(req)
    }
}