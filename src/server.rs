//! HTTP/1.1 accept loop with connection-level resource bounds.
//!
//! `axum::serve` builds hyper's connection builder without a timer, so hyper's
//! header-read timeout never applies and an unbounded number of idle or
//! trickling connections can be held open. This loop serves the same router
//! over HTTP/1.1 with a timer, an explicit header-read timeout, and a
//! process-wide connection cap.
//!
//! There is deliberately no whole-request timeout: event streams, uploads, and
//! downloads are long-lived and carry their own bounds.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, body::Body, extract::Request};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tower::{Service, ServiceExt};

/// Connection-level bounds applied by [`serve`].
#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    /// Maximum simultaneously open client connections. Connections accepted
    /// above the cap are closed immediately without reading from them.
    pub max_connections: usize,
    /// Time a client has to send a complete request head, measured from when
    /// the server starts waiting for it. This covers a new connection and an
    /// idle keep-alive connection between requests; it does not cover request
    /// bodies or responses.
    pub header_read_timeout: Duration,
}

/// Serves `app` on `listener` until the process exits. The router receives
/// `ConnectInfo<SocketAddr>` exactly as with
/// `into_make_service_with_connect_info::<SocketAddr>()`.
pub async fn serve(mut listener: TcpListener, app: Router, limits: ServerLimits) {
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .keep_alive(true);
    let mut saturated = false;
    loop {
        // axum's listener retries transient accept errors and backs off on
        // others, such as file-descriptor exhaustion.
        let (stream, remote_addr) = axum::serve::Listener::accept(&mut listener).await;
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            drop(stream);
            if !saturated {
                saturated = true;
                tracing::warn!(
                    max_connections = limits.max_connections,
                    "connection limit reached; closing new connections until one is released"
                );
            }
            continue;
        };
        saturated = false;
        let service = ServiceExt::<SocketAddr>::ready(&mut make_service)
            .await
            .unwrap_or_else(|error: Infallible| match error {})
            .call(remote_addr)
            .await
            .unwrap_or_else(|error: Infallible| match error {});
        let service = TowerToHyperService::new(
            service.map_request(|request: Request<Incoming>| request.map(Body::new)),
        );
        let builder = builder.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let connection = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            match connection.await {
                Ok(()) => {}
                Err(error) if error.is_timeout() => {
                    tracing::debug!("connection closed by the header-read timeout");
                }
                Err(error) => tracing::debug!(%error, "connection closed with an error"),
            }
        });
    }
}
