use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use axum::{Router, extract::ConnectInfo, routing::get};
use crabinet::server::{ServerLimits, serve};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const PATIENCE: Duration = Duration::from_secs(10);

/// A cap with a header-read timeout long enough not to interfere.
const fn limits(max_connections: usize) -> ServerLimits {
    ServerLimits {
        max_connections,
        header_read_timeout: Duration::from_secs(300),
    }
}

async fn start(limits: ServerLimits) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    );
    tokio::spawn(serve(listener, app, limits));
    address
}

/// Sends one keep-alive request and reads exactly one response.
async fn request(stream: &mut TcpStream) -> String {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    timeout(PATIENCE, async {
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "connection closed before a complete response");
            response.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&response);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if body.len() >= length {
                    return;
                }
            }
        }
    })
    .await
    .expect("response in time");
    String::from_utf8(response).unwrap()
}

/// Reads until the server closes the connection; returns what it sent.
async fn read_until_closed(stream: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    timeout(PATIENCE, async {
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => received.extend_from_slice(&buffer[..read]),
            }
        }
    })
    .await
    .expect("server closed the connection");
    received
}

#[tokio::test]
async fn router_receives_the_peer_address() {
    let address = start(limits(4)).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let local = stream.local_addr().unwrap();
    let response = request(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with(&local.to_string()), "{response}");
}

#[tokio::test]
async fn incomplete_request_head_is_closed_after_the_header_timeout() {
    let header_read_timeout = Duration::from_millis(300);
    let address = start(ServerLimits {
        max_connections: 4,
        header_read_timeout,
    })
    .await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let started = Instant::now();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: exa")
        .await
        .unwrap();
    let received = read_until_closed(&mut stream).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= header_read_timeout - Duration::from_millis(50),
        "{elapsed:?}"
    );
    assert!(elapsed < PATIENCE, "{elapsed:?}");
    let text = String::from_utf8_lossy(&received);
    assert!(received.is_empty(), "{text}");
}

#[tokio::test]
async fn idle_keep_alive_connection_is_closed_after_the_header_timeout() {
    let header_read_timeout = Duration::from_millis(300);
    let address = start(ServerLimits {
        max_connections: 4,
        header_read_timeout,
    })
    .await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    assert!(request(&mut stream).await.starts_with("HTTP/1.1 200"));
    let started = Instant::now();
    let received = read_until_closed(&mut stream).await;
    assert!(started.elapsed() < PATIENCE);
    let text = String::from_utf8_lossy(&received);
    assert!(received.is_empty(), "{text}");
}

#[tokio::test]
async fn connections_above_the_cap_are_closed_while_admitted_ones_keep_working() {
    let address = start(limits(2)).await;
    let mut first = TcpStream::connect(address).await.unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    assert!(request(&mut first).await.starts_with("HTTP/1.1 200"));
    assert!(request(&mut second).await.starts_with("HTTP/1.1 200"));

    let mut rejected = TcpStream::connect(address).await.unwrap();
    // The request may or may not be written before the close arrives.
    let _ = rejected
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await;
    assert!(read_until_closed(&mut rejected).await.is_empty());

    assert!(request(&mut first).await.starts_with("HTTP/1.1 200"));
    assert!(request(&mut second).await.starts_with("HTTP/1.1 200"));

    // Closing an admitted connection releases its slot.
    drop(first);
    let deadline = Instant::now() + PATIENCE;
    loop {
        let mut stream = TcpStream::connect(address).await.unwrap();
        if stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .is_ok()
        {
            let mut buffer = [0_u8; 12];
            if matches!(
                timeout(PATIENCE, stream.read_exact(&mut buffer)).await,
                Ok(Ok(_))
            ) {
                assert_eq!(&buffer, b"HTTP/1.1 200");
                break;
            }
        }
        assert!(Instant::now() < deadline, "slot was never released");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
