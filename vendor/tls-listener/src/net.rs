use super::AsyncAccept;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg_attr(docsrs, doc(cfg(feature = "tokio-net")))]
impl AsyncAccept for TcpListener {
    type Connection = TcpStream;
    type Error = io::Error;
    type Address = std::net::SocketAddr;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Self::Connection, Self::Address), Self::Error>> {
        match (*self).poll_accept(cx) {
            Poll::Ready(Ok(conn)) => Poll::Ready(Ok(conn)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(unix)]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-net")))]
impl AsyncAccept for UnixListener {
    type Connection = UnixStream;
    type Error = io::Error;
    type Address = tokio::net::unix::SocketAddr;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Self::Connection, Self::Address), Self::Error>> {
        match (*self).poll_accept(cx) {
            Poll::Ready(Ok(conn)) => Poll::Ready(Ok(conn)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
