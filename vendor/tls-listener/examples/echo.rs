use futures_util::StreamExt;
use std::net::SocketAddr;
use tls_listener::TlsListener;
use tokio::io::{copy, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::ctrl_c;

#[cfg(all(
    feature = "native-tls",
    not(any(feature = "rustls-core", feature = "openssl"))
))]
use tokio_native_tls::TlsStream;
#[cfg(all(
    feature = "openssl",
    not(any(feature = "rustls-core", feature = "native-tls"))
))]
use tokio_openssl::SslStream as TlsStream;
#[cfg(feature = "rustls-core")]
use tokio_rustls::server::TlsStream;

mod tls_config;
use tls_config::tls_acceptor;

#[inline]
async fn handle_stream(stream: TlsStream<TcpStream>, _remote_addr: SocketAddr) {
    let (mut reader, mut writer) = split(stream);
    match copy(&mut reader, &mut writer).await {
        Ok(cnt) => eprintln!("Processed {} bytes", cnt),
        Err(err) => eprintln!("Error during copy: {}", err),
    };
}

/// For example try opening and closing a connection with:
/// `echo "Q" | openssl s_client -connect localhost:3000`
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    let listener = TcpListener::bind(&addr).await?;

    TlsListener::new(tls_acceptor(), listener)
        .take_until(ctrl_c())
        .for_each_concurrent(None, |s| async {
            match s {
                Ok((stream, remote_addr)) => {
                    handle_stream(stream, remote_addr).await;
                }
                Err(e) => {
                    if let Some(remote_addr) = e.peer_addr() {
                        eprint!("[client {remote_addr}] ");
                    }

                    eprintln!("Error accepting connection: {:?}", e);
                }
            }
        })
        .await;
    Ok(())
}
