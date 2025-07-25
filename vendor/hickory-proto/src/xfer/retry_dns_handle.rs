// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `RetryDnsHandle` allows for DnsQueries to be reattempted on failure

#[cfg(any(feature = "std", feature = "no-std-rand"))]
use alloc::boxed::Box;
use core::pin::Pin;
use core::task::{Context, Poll};

use futures_util::stream::{Stream, StreamExt};

use crate::DnsHandle;
use crate::error::{ProtoError, ProtoErrorKind};
use crate::xfer::{DnsRequest, DnsResponse};

/// Can be used to reattempt queries if they fail
///
/// Note: this does not reattempt queries that fail with a negative response.
/// For example, if a query gets a `NODATA` response from a name server, the
/// query will not be retried. It only reattempts queries that effectively
/// failed to get a response, such as queries that resulted in IO or timeout
/// errors.
///
/// Whether an error is retryable by the [`RetryDnsHandle`] is determined by the
/// [`RetryableError`] trait.
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
#[allow(dead_code)]
pub struct RetryDnsHandle<H>
where
    H: DnsHandle + Unpin + Send,
{
    handle: H,
    attempts: usize,
}

impl<H> RetryDnsHandle<H>
where
    H: DnsHandle + Unpin + Send,
{
    /// Creates a new Client handler for reattempting requests on failures.
    ///
    /// # Arguments
    ///
    /// * `handle` - handle to the dns connection
    /// * `attempts` - number of attempts before failing
    pub fn new(handle: H, attempts: usize) -> Self {
        Self { handle, attempts }
    }
}

#[cfg(any(feature = "std", feature = "no-std-rand"))]
impl<H: DnsHandle> DnsHandle for RetryDnsHandle<H> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;

    fn send(&self, request: DnsRequest) -> Self::Response {
        // need to clone here so that the retry can resend if necessary...
        //  obviously it would be nice to be lazy about this...
        let stream = self.handle.send(request.clone());

        Box::pin(RetrySendStream {
            request,
            handle: self.handle.clone(),
            stream,
            remaining_attempts: self.attempts,
        })
    }
}

/// A stream for retrying (on failure, for the remaining number of times specified)
struct RetrySendStream<H>
where
    H: DnsHandle,
{
    request: DnsRequest,
    handle: H,
    stream: <H as DnsHandle>::Response,
    remaining_attempts: usize,
}

impl<H: DnsHandle + Unpin> Stream for RetrySendStream<H> {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // loop over the stream, on errors, spawn a new stream
        //  on ready and not ready return.
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Err(e))) => {
                    if self.remaining_attempts == 0 || !e.should_retry() {
                        return Poll::Ready(Some(Err(e)));
                    }

                    if e.attempted() {
                        self.remaining_attempts -= 1;
                    }

                    // TODO: if the "sent" Message is part of the error result,
                    //  then we can just reuse it... and no clone necessary
                    let request = self.request.clone();
                    self.stream = self.handle.send(request);
                }
                poll => return poll,
            }
        }
    }
}

/// What errors should be retried
pub trait RetryableError {
    /// Whether the query should be retried after this error
    fn should_retry(&self) -> bool;
    /// Whether this error should count as an attempt
    fn attempted(&self) -> bool;
}

impl RetryableError for ProtoError {
    fn should_retry(&self) -> bool {
        !matches!(
            self.kind(),
            ProtoErrorKind::NoConnections | ProtoErrorKind::NoRecordsFound { .. }
        )
    }

    fn attempted(&self) -> bool {
        !matches!(self.kind(), ProtoErrorKind::Busy)
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU16, Ordering};

    use super::*;
    use crate::error::*;
    use crate::op::*;
    use crate::xfer::FirstAnswer;

    use futures_executor::block_on;
    use futures_util::future::{err, ok};
    use futures_util::stream::*;
    use test_support::subscribe;

    #[derive(Clone)]
    struct TestClient {
        last_succeed: bool,
        retries: u16,
        attempts: Arc<AtomicU16>,
    }

    impl DnsHandle for TestClient {
        type Response = Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>;

        fn send(&self, _: DnsRequest) -> Self::Response {
            let i = self.attempts.load(Ordering::SeqCst);

            if (i > self.retries || self.retries - i == 0) && self.last_succeed {
                let mut message = Message::query();
                message.set_id(i);
                return Box::new(once(ok(DnsResponse::from_message(message).unwrap())));
            }

            self.attempts.fetch_add(1, Ordering::SeqCst);
            Box::new(once(err(ProtoError::from("last retry set to fail"))))
        }
    }

    #[test]
    fn test_retry() {
        subscribe();
        let handle = RetryDnsHandle::new(
            TestClient {
                last_succeed: true,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = DnsRequest::from(Message::query());
        let result = block_on(handle.send(test1).first_answer()).expect("should have succeeded");
        assert_eq!(result.id(), 1); // this is checking the number of iterations the TestClient ran
    }

    #[test]
    fn test_error() {
        subscribe();
        let client = RetryDnsHandle::new(
            TestClient {
                last_succeed: false,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = DnsRequest::from(Message::query());
        assert!(block_on(client.send(test1).first_answer()).is_err());
    }
}
