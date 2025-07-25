// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use std::{clone::Clone, collections::HashSet, error::Error, pin::Pin, sync::Arc};

use futures_util::{
    future::{self, Future, FutureExt, TryFutureExt},
    stream::{self, Stream, TryStreamExt},
};
use tracing::{debug, trace};

use crate::{
    error::{ProtoError, ProtoErrorKind, ProtoResult},
    op::{Edns, OpCode, Query},
    rr::{
        dnssec::{
            rdata::{DNSSECRData, DNSKEY, RRSIG},
            Algorithm, SupportedAlgorithms, TrustAnchor,
        },
        rdata::opt::EdnsOption,
        DNSClass, Name, RData, Record, RecordData, RecordType,
    },
    xfer::{dns_handle::DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse, FirstAnswer},
};

#[cfg(feature = "dnssec")]
use crate::rr::dnssec::Verifier;

#[derive(Debug)]
struct Rrset {
    pub(crate) name: Name,
    pub(crate) record_type: RecordType,
    pub(crate) record_class: DNSClass,
    pub(crate) records: Vec<Record>,
}

/// Performs DNSSEC validation of all DNS responses from the wrapped DnsHandle
///
/// This wraps a DnsHandle, changing the implementation `send()` to validate all
///  message responses for Query operations. Update operation responses are not validated by
///  this process.
#[derive(Clone)]
#[must_use = "queries can only be sent through a DnsHandle"]
pub struct DnssecDnsHandle<H>
where
    H: DnsHandle + Unpin + 'static,
{
    handle: H,
    trust_anchor: Arc<TrustAnchor>,
    request_depth: usize,
    minimum_key_len: usize,
    minimum_algorithm: Algorithm, // used to prevent down grade attacks...
}

impl<H> DnssecDnsHandle<H>
where
    H: DnsHandle + Unpin + 'static,
{
    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This uses the compiled in TrustAnchor default trusted keys.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    pub fn new(handle: H) -> Self {
        Self::with_trust_anchor(handle, TrustAnchor::default())
    }

    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This allows a custom TrustAnchor to be define.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    /// * `trust_anchor` - custom DNSKEYs that will be trusted, can be used to pin trusted keys.
    pub fn with_trust_anchor(handle: H, trust_anchor: TrustAnchor) -> Self {
        Self {
            handle,
            trust_anchor: Arc::new(trust_anchor),
            request_depth: 0,
            minimum_key_len: 0,
            minimum_algorithm: Algorithm::RSASHA256,
        }
    }

    /// An internal function used to clone the handle, but maintain some information back to the
    ///  original handle, such as the request_depth such that infinite recursion does
    ///  not occur.
    fn clone_with_context(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            trust_anchor: Arc::clone(&self.trust_anchor),
            request_depth: self.request_depth + 1,
            minimum_key_len: self.minimum_key_len,
            minimum_algorithm: self.minimum_algorithm,
        }
    }
}

impl<H> DnsHandle for DnssecDnsHandle<H>
where
    H: DnsHandle + Sync + Unpin,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, Self::Error>> + Send>>;
    type Error = <H as DnsHandle>::Error;

    fn is_verifying_dnssec(&self) -> bool {
        // This handler is always verifying...
        true
    }

    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        let mut request = request.into();

        // backstop
        if self.request_depth > request.options().max_request_depth {
            return Box::pin(stream::once(future::err(Self::Error::from(
                ProtoError::from("exceeded max validation depth"),
            ))));
        }

        // dnssec only matters on queries.
        if let OpCode::Query = request.op_code() {
            // This will panic on no queries, that is a very odd type of request, isn't it?
            // TODO: with mDNS there can be multiple queries
            let query = request
                .queries()
                .first()
                .cloned()
                .expect("no queries in request");
            let handle: Self = self.clone_with_context();

            // TODO: cache response of the server about understood algorithms
            #[cfg(feature = "dnssec")]
            {
                let edns = request.extensions_mut().get_or_insert_with(Edns::new);
                edns.set_dnssec_ok(true);

                // send along the algorithms which are supported by this handle
                let mut algorithms = SupportedAlgorithms::new();
                #[cfg(feature = "ring")]
                {
                    algorithms.set(Algorithm::ED25519);
                }
                algorithms.set(Algorithm::ECDSAP256SHA256);
                algorithms.set(Algorithm::ECDSAP384SHA384);
                algorithms.set(Algorithm::RSASHA256);

                let dau = EdnsOption::DAU(algorithms);
                let dhu = EdnsOption::DHU(algorithms);

                edns.options_mut().insert(dau);
                edns.options_mut().insert(dhu);
            }

            request.set_authentic_data(true);
            request.set_checking_disabled(false);
            let dns_class = request
                .queries()
                .first()
                .map_or(DNSClass::IN, Query::query_class);
            let options = *request.options();

            return Box::pin(
                self.handle
                    .send(request)
                    .and_then(move |message_response| {
                        // group the record sets by name and type
                        //  each rrset type needs to validated independently
                        debug!(
                            "validating message_response: {}, with {} trust_anchors",
                            message_response.id(),
                            handle.trust_anchor.len(),
                        );
                        verify_rrsets(handle.clone(), message_response, dns_class, options)
                    })
                    .and_then(move |verified_message| {
                        // at this point all of the message is verified.
                        //  This is where NSEC (and possibly NSEC3) validation occurs
                        // As of now, only NSEC is supported.
                        if verified_message.answers().is_empty() {
                            // get SOA name
                            let soa_name = if let Some(soa_name) = verified_message
                                .name_servers()
                                .iter()
                                // there should only be one
                                .find(|rr| rr.record_type() == RecordType::SOA)
                                .map(Record::name)
                            {
                                soa_name
                            } else {
                                return future::err(Self::Error::from(ProtoError::from(
                                    "could not validate negative response missing SOA",
                                )));
                            };

                            let nsecs = verified_message
                                .name_servers()
                                .iter()
                                .filter(|rr| is_dnssec(rr, RecordType::NSEC))
                                .collect::<Vec<_>>();

                            if !verify_nsec(&query, soa_name, nsecs.as_slice()) {
                                // TODO change this to remove the NSECs, like we do for the others?
                                return future::err(Self::Error::from(ProtoError::from(
                                    "could not validate negative response with NSEC",
                                )));
                            }
                        }

                        future::ok(verified_message)
                    }),
            );
        }

        Box::pin(self.handle.send(request))
    }
}

/// this pulls all records returned in a Message response and returns a future which will
///  validate all of them.
#[allow(clippy::type_complexity)]
async fn verify_rrsets<H, E>(
    handle: DnssecDnsHandle<H>,
    message_result: DnsResponse,
    dns_class: DNSClass,
    options: DnsRequestOptions,
) -> Result<DnsResponse, E>
where
    H: DnsHandle<Error = E> + Sync + Unpin,
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();
    for rrset in message_result
        .answers()
        .iter()
        .chain(message_result.name_servers())
        .filter(|rr| {
            !is_dnssec(rr, RecordType::RRSIG) &&
                             // if we are at a depth greater than 1, we are only interested in proving evaluation chains
                             //   this means that only DNSKEY and DS are interesting at that point.
                             //   this protects against looping over things like NS records and DNSKEYs in responses.
                             // TODO: is there a cleaner way to prevent cycles in the evaluations?
                                          (handle.request_depth <= 1 ||
                                           is_dnssec(rr, RecordType::DNSKEY) ||
                                           is_dnssec(rr, RecordType::DS))
        })
        .map(|rr| (rr.name().clone(), rr.record_type()))
    {
        rrset_types.insert(rrset);
    }

    // there was no data returned in that message
    if rrset_types.is_empty() {
        let mut message_result = message_result.into_message();

        // there were no returned results, double check by dropping all the results
        message_result.take_answers();
        message_result.take_name_servers();
        message_result.take_additionals();

        return Err(E::from(ProtoError::from(ProtoErrorKind::Message(
            "no results to verify",
        ))));
    }

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    let mut rrsets_to_verify = Vec::with_capacity(rrset_types.len());
    for (name, record_type) in rrset_types {
        // TODO: should we evaluate the different sections (answers and name_servers) separately?
        let records: Vec<Record> = message_result
            .answers()
            .iter()
            .chain(message_result.name_servers())
            .chain(message_result.additionals())
            .filter(|rr| rr.record_type() == record_type && rr.name() == &name)
            .cloned()
            .collect();

        let rrsigs: Vec<Record<RRSIG>> = message_result
            .answers()
            .iter()
            .chain(message_result.name_servers())
            .chain(message_result.additionals())
            .filter(|rr| is_dnssec(rr, RecordType::RRSIG))
            .filter(|rr| {
                if let Some(RData::DNSSEC(DNSSECRData::RRSIG(ref rrsig))) = rr.data() {
                    rrsig.type_covered() == record_type
                } else {
                    false
                }
            })
            .cloned()
            .map(|rr| Record::<RRSIG>::try_from(rr).expect("the record type was checked above"))
            .collect();

        // if there is already an active validation going on, assume the other validation will
        //  complete properly or error if it is invalid
        let rrset = Rrset {
            name,
            record_type,
            record_class: dns_class,
            records,
        };

        // TODO: support non-IN classes?
        debug!(
            "verifying: {}, record_type: {:?}, rrsigs: {}",
            rrset.name,
            record_type,
            rrsigs.len()
        );
        rrsets_to_verify
            .push(verify_rrset(handle.clone_with_context(), rrset, rrsigs, options).boxed());
    }

    // spawn a select_all over this vec, these are the individual RRSet validators
    verify_all_rrsets(message_result, rrsets_to_verify).await
}

// TODO: is this method useful/necessary?
fn is_dnssec<D: RecordData>(rr: &Record<D>, dnssec_type: RecordType) -> bool {
    rr.record_type().is_dnssec() && dnssec_type.is_dnssec() && rr.record_type() == dnssec_type
}

async fn verify_all_rrsets<F, E>(
    message_result: DnsResponse,
    rrsets: Vec<F>,
) -> Result<DnsResponse, E>
where
    F: Future<Output = Result<Rrset, E>> + Send + Unpin,
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    let mut verified_rrsets: HashSet<(Name, RecordType)> = HashSet::new();
    let mut rrsets = future::select_all(rrsets);
    let mut last_validation_err: Option<E> = None;

    // loop through all the rrset evaluations, filter all the rrsets in the Message
    //  down to just the ones that were able to be validated
    loop {
        let (rrset, _, remaining) = rrsets.await;
        match rrset {
            Ok(rrset) => {
                debug!(
                    "an rrset was verified: {}, {:?}",
                    rrset.name, rrset.record_type
                );
                verified_rrsets.insert((rrset.name, rrset.record_type));
            }
            // TODO: should we return the Message on errors? Allow the consumer to decide what to do
            //       on a validation failure?
            // any error, is an error for all
            Err(e) => {
                if tracing::enabled!(tracing::Level::DEBUG) {
                    let mut query = message_result
                        .queries()
                        .iter()
                        .map(|q| q.to_string())
                        .fold(String::new(), |s, q| format!("{q},{s}"));

                    query.truncate(query.len() - 1);
                    debug!("an rrset failed to verify ({}): {:?}", query, e);
                }

                last_validation_err = Some(e);
            }
        };

        if !remaining.is_empty() {
            // continue the evaluation
            rrsets = future::select_all(remaining);
        } else {
            break;
        }
    }

    // check if any are valid, otherwise return whatever error caused it to fail
    if verified_rrsets.is_empty() {
        if let Some(last_validation_err) = last_validation_err {
            return Err(last_validation_err);
        }
    }

    // validated not none above...
    let (mut message_result, message_buffer) = message_result.into_parts();

    // take all the rrsets from the Message, filter down each set to the validated rrsets
    // TODO: does the section in the message matter here?
    //       we could probably end up with record_types in any section.
    //       track the section in the rrset evaluation?
    let answers = message_result
        .take_answers()
        .into_iter()
        .chain(message_result.take_additionals().into_iter())
        .filter(|record| verified_rrsets.contains(&(record.name().clone(), record.record_type())))
        .collect::<Vec<Record>>();

    let name_servers = message_result
        .take_name_servers()
        .into_iter()
        .filter(|record| verified_rrsets.contains(&(record.name().clone(), record.record_type())))
        .collect::<Vec<Record>>();

    let additionals = message_result
        .take_additionals()
        .into_iter()
        .filter(|record| verified_rrsets.contains(&(record.name().clone(), record.record_type())))
        .collect::<Vec<Record>>();

    // add the filtered records back to the message
    message_result.insert_answers(answers);
    message_result.insert_name_servers(name_servers);
    message_result.insert_additionals(additionals);

    // breaks out of the loop... and returns the filtered Message.
    Ok(DnsResponse::new(message_result, message_buffer))
}

/// Generic entrypoint to verify any RRset against the provided signatures.
///
/// Generally, the RRset will be validated by `verify_default_rrset()`. In the case of DNSKEYs, the
/// RRset will be validated by `verify_dnskey_rrset()`. If it's an NSEC record, then the NSEC
/// record will be validated to prove it's correctness.
async fn verify_rrset<H, E>(
    handle: DnssecDnsHandle<H>,
    rrset: Rrset,
    rrsigs: Vec<Record<RRSIG>>,
    options: DnsRequestOptions,
) -> Result<Rrset, E>
where
    H: DnsHandle<Error = E> + Sync + Unpin,
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    match rrset.record_type {
        RecordType::DNSKEY => verify_dnskey_rrset(handle, rrset, rrsigs, options).await,
        _ => verify_default_rrset(&handle.clone_with_context(), rrset, rrsigs, options).await,
    }
}

/// Verifies a DNSKEY RRset
///
/// This first checks to see if any key is in the set of trust_anchors. If not, a query is sent to
/// get the DS record, and each DNSKEY is validated against the DS record. Then, the DNSKEY RRset is
/// validated using signatures made by authenticated keys.
async fn verify_dnskey_rrset<H, E>(
    handle: DnssecDnsHandle<H>,
    rrset: Rrset,
    rrsigs: Vec<Record<RRSIG>>,
    options: DnsRequestOptions,
) -> Result<Rrset, E>
where
    H: DnsHandle<Error = E> + Sync + Unpin,
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    trace!(
        "dnskey validation {}, record_type: {:?}",
        rrset.name,
        rrset.record_type
    );

    // check the DNSKEYS against the trust_anchor, if it's approved allow it.
    {
        let anchored_keys = rrset
            .records
            .iter()
            .enumerate()
            .filter(|&(_, rr)| is_dnssec(rr, RecordType::DNSKEY))
            .filter_map(|(i, rr)| rr.data().map(|rr| (i, rr)))
            .filter_map(|(i, rr)| DNSKEY::try_borrow(rr).map(|rr| (i, rr)))
            .filter_map(|(i, rdata)| {
                if handle
                    .trust_anchor
                    .contains_dnskey_bytes(rdata.public_key())
                {
                    debug!(
                        "validated dnskey with trust_anchor: {}, {}",
                        rrset.name, rdata
                    );

                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<usize>>();

        // Verify the self-signature over the DNSKEY RRset.
        for dnskey_index in anchored_keys.iter().copied() {
            let dnskey_record = &rrset.records[dnskey_index];
            let Some(RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))) = dnskey_record.data() else {
                continue;
            };
            for rrsig_record in rrsigs.iter() {
                let Some(rrsig) = rrsig_record.data() else {
                    continue;
                };
                let verify_result = verify_rrset_with_dnskey(&rrset.name, dnskey, rrsig, &rrset);
                if verify_result.is_ok() {
                    return Ok(rrset);
                }
            }
        }

        if anchored_keys.len() == rrset.records.len() {
            // Special case: allow a zone consisting of only trust anchor keys without a
            // self-signature.
            return Ok(rrset);
        }
    }

    // need to get DS records for each DNSKEY
    let ds_message = handle
        .lookup(Query::query(rrset.name.clone(), RecordType::DS), options)
        .first_answer()
        .await?;
    let valid_keys = rrset
        .records
        .iter()
        .enumerate()
        .filter(|&(_, rr)| is_dnssec(rr, RecordType::DNSKEY))
        .filter_map(|(i, rr)| {
            if let Some(RData::DNSSEC(DNSSECRData::DNSKEY(ref rdata))) = rr.data() {
                Some((i, rdata))
            } else {
                None
            }
        })
        .filter(|&(_, key_rdata)| {
            ds_message
                .answers()
                .iter()
                .filter(|ds| is_dnssec(ds, RecordType::DS))
                .filter_map(|ds| {
                    if let Some(RData::DNSSEC(DNSSECRData::DS(ref ds_rdata))) = ds.data() {
                        Some((ds.name(), ds_rdata))
                    } else {
                        None
                    }
                })
                // must be covered by at least one DS record
                .any(|(ds_name, ds_rdata)| {
                    if ds_rdata.covers(&rrset.name, key_rdata).unwrap_or(false) {
                        debug!(
                            "validated dnskey ({}, {}) with {} {}",
                            rrset.name, key_rdata, ds_name, ds_rdata
                        );

                        true
                    } else {
                        false
                    }
                })
        })
        .map(|(i, _)| i)
        .collect::<Vec<usize>>();

    if !valid_keys.is_empty() {
        trace!("validated dnskey: {}", rrset.name);
    }

    for dnskey_index in valid_keys {
        let dnskey_record = &rrset.records[dnskey_index];
        let Some(RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))) = dnskey_record.data() else {
            continue;
        };
        for rrsig_record in rrsigs.iter() {
            let Some(rrsig) = rrsig_record.data() else {
                continue;
            };
            let verify_result = verify_rrset_with_dnskey(&rrset.name, dnskey, rrsig, &rrset);
            if verify_result.is_ok() {
                return Ok(rrset);
            }
        }
    }

    Err(E::from(ProtoError::from(ProtoErrorKind::Message(
        "Could not validate all DNSKEYs",
    ))))
}

/// Verifies that a given RRSET is validly signed by any of the specified RRSIGs.
///
/// Invalid RRSIGs will be ignored. RRSIGs will only be validated against DNSKEYs which can
///  be validated through a chain back to the `trust_anchor`. As long as one RRSIG is valid,
///  then the RRSET will be valid.
#[allow(clippy::blocks_in_conditions)]
async fn verify_default_rrset<H, E>(
    handle: &DnssecDnsHandle<H>,
    rrset: Rrset,
    rrsigs: Vec<Record<RRSIG>>,
    options: DnsRequestOptions,
) -> Result<Rrset, E>
where
    H: DnsHandle<Error = E> + Sync + Unpin,
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    // the record set is going to be shared across a bunch of futures, Arc for that.
    let rrset = Arc::new(rrset);
    trace!(
        "default validation {}, record_type: {:?}",
        rrset.name,
        rrset.record_type
    );

    // we can validate with any of the rrsigs...
    //  i.e. the first that validates is good enough
    //  TODO: could there be a cert downgrade attack here with a MITM stripping stronger RRSIGs?
    //         we could check for the strongest RRSIG and only use that...
    //         though, since the entire package isn't signed any RRSIG could have been injected,
    //         right? meaning if there is an attack on any of the acceptable algorithms, we'd be
    //         susceptible until that algorithm is removed as an option.
    //        dns over TLS will mitigate this.
    //  TODO: strip RRSIGS to accepted algorithms and make algorithms configurable.
    let verifications = rrsigs.into_iter()
        // this filter is technically unnecessary, can probably remove it...
        .filter(|rrsig| is_dnssec(rrsig, RecordType::RRSIG))
        .filter_map(|rrsig|rrsig.into_data())
        .map(|sig| {
            let rrset = Arc::clone(&rrset);
            let handle = handle.clone_with_context();

            handle
                .lookup(
                    Query::query(sig.signer_name().clone(), RecordType::DNSKEY),
                    options,
                )
                .first_answer()
                .and_then(move |message|
                    // DNSKEYs are validated by the inner query
                    future::ready(message
                        .answers()
                        .iter()
                        .filter(|r| is_dnssec(r, RecordType::DNSKEY))
                        .filter_map(|r| r.data().map(|data| (r.name(), data)))
                        .filter_map(|(dnskey_name, data)|
                           DNSKEY::try_borrow(data).map(|data| (dnskey_name, data)))
                        .find(|(dnskey_name, dnskey)|
                                verify_rrset_with_dnskey(dnskey_name, dnskey, &sig, &rrset).is_ok()
                        )
                        .map(|_| ())
                        .ok_or_else(|| E::from(ProtoError::from(ProtoErrorKind::Message("validation failed")))))
                )
        })
        .collect::<Vec<_>>();

    // if there are no available verifications, then we are in a failed state.
    if verifications.is_empty() {
        return Err(E::from(ProtoError::from(
            ProtoErrorKind::RrsigsNotPresent {
                name: rrset.name.clone(),
                record_type: rrset.record_type,
            },
        )));
    }

    // as long as any of the verifications is good, then the RRSET is valid.
    let select = future::select_ok(verifications)
        // getting here means at least one of the rrsigs succeeded...
        .map_ok(move |((), rest)| {
            drop(rest); // drop all others, should free up Arc
            Arc::try_unwrap(rrset).expect("unable to unwrap Arc")
        });

    select.await
}

/// Verifies the given SIG of the RRSET with the DNSKEY.
#[cfg(feature = "dnssec")]
fn verify_rrset_with_dnskey(
    dnskey_name: &Name,
    dnskey: &DNSKEY,
    sig: &RRSIG,
    rrset: &Rrset,
) -> ProtoResult<()> {
    if dnskey.revoke() {
        debug!("revoked");
        return Err(ProtoErrorKind::Message("revoked").into());
    } // TODO: does this need to be validated? RFC 5011
    if !dnskey.zone_key() {
        return Err(ProtoErrorKind::Message("is not a zone key").into());
    }
    if dnskey.algorithm() != sig.algorithm() {
        return Err(ProtoErrorKind::Message("mismatched algorithm").into());
    }

    dnskey
        .verify_rrsig(&rrset.name, rrset.record_class, sig, &rrset.records)
        .map(|r| {
            debug!(
                "validated ({}, {:?}) with ({}, {})",
                rrset.name, rrset.record_type, dnskey_name, dnskey
            );
            r
        })
        .map_err(Into::into)
        .map_err(|e| {
            debug!(
                "failed validation of ({}, {:?}) with ({}, {})",
                rrset.name, rrset.record_type, dnskey_name, dnskey
            );
            e
        })
}

/// Will always return an error. To enable record verification compile with the openssl feature.
#[cfg(not(feature = "dnssec"))]
fn verify_rrset_with_dnskey(_: &DNSKEY, _: &RRSIG, _: &Rrset) -> ProtoResult<()> {
    Err(ProtoErrorKind::Message("openssl or ring feature(s) not enabled").into())
}

/// Verifies NSEC records
///
/// ```text
/// RFC 4035             DNSSEC Protocol Modifications            March 2005
///
/// 5.4.  Authenticated Denial of Existence
///
///  A resolver can use authenticated NSEC RRs to prove that an RRset is
///  not present in a signed zone.  Security-aware name servers should
///  automatically include any necessary NSEC RRs for signed zones in
///  their responses to security-aware resolvers.
///
///  Denial of existence is determined by the following rules:
///
///  o  If the requested RR name matches the owner name of an
///     authenticated NSEC RR, then the NSEC RR's type bit map field lists
///     all RR types present at that owner name, and a resolver can prove
///     that the requested RR type does not exist by checking for the RR
///     type in the bit map.  If the number of labels in an authenticated
///     NSEC RR's owner name equals the Labels field of the covering RRSIG
///     RR, then the existence of the NSEC RR proves that wildcard
///     expansion could not have been used to match the request.
///
///  o  If the requested RR name would appear after an authenticated NSEC
///     RR's owner name and before the name listed in that NSEC RR's Next
///     Domain Name field according to the canonical DNS name order
///     defined in [RFC4034], then no RRsets with the requested name exist
///     in the zone.  However, it is possible that a wildcard could be
///     used to match the requested RR owner name and type, so proving
///     that the requested RRset does not exist also requires proving that
///     no possible wildcard RRset exists that could have been used to
///     generate a positive response.
///
///  In addition, security-aware resolvers MUST authenticate the NSEC
///  RRsets that comprise the non-existence proof as described in Section
///  5.3.
///
///  To prove the non-existence of an RRset, the resolver must be able to
///  verify both that the queried RRset does not exist and that no
///  relevant wildcard RRset exists.  Proving this may require more than
///  one NSEC RRset from the zone.  If the complete set of necessary NSEC
///  RRsets is not present in a response (perhaps due to message
///  truncation), then a security-aware resolver MUST resend the query in
///  order to attempt to obtain the full collection of NSEC RRs necessary
///  to verify the non-existence of the requested RRset.  As with all DNS
///  operations, however, the resolver MUST bound the work it puts into
///  answering any particular query.
///
///  Since a validated NSEC RR proves the existence of both itself and its
///  corresponding RRSIG RR, a validator MUST ignore the settings of the
///  NSEC and RRSIG bits in an NSEC RR.
/// ```
#[allow(clippy::blocks_in_conditions)]
#[doc(hidden)]
pub fn verify_nsec(query: &Query, soa_name: &Name, nsecs: &[&Record]) -> bool {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if let Some(nsec) = nsecs.iter().find(|nsec| query.name() == nsec.name()) {
        return nsec
            .data()
            .and_then(RData::as_dnssec)
            .and_then(DNSSECRData::as_nsec)
            .is_some_and(|rdata| {
                // this should not be in the covered list
                !rdata.type_bit_maps().contains(&query.query_type())
            });
    }

    let verify_nsec_coverage = |name: &Name| -> bool {
        nsecs.iter().any(|nsec| {
            // the query name must be greater than nsec's label (or equal in the case of wildcard)
            name >= nsec.name() && {
                nsec.data()
                    .and_then(RData::as_dnssec)
                    .and_then(DNSSECRData::as_nsec)
                    .is_some_and(|rdata| {
                        // the query name is less than the next name
                        // or this record wraps the end, i.e. is the last record
                        name < rdata.next_domain_name() || rdata.next_domain_name() < nsec.name()
                    })
            }
        })
    };

    if !verify_nsec_coverage(query.name()) {
        // continue to validate there is no wildcard
        return false;
    }

    // validate ANY or *.domain record existence

    // we need the wildcard proof, but make sure that it's still part of the zone.
    let wildcard = query.name().base_name();
    let wildcard = if soa_name.zone_of(&wildcard) {
        wildcard
    } else {
        soa_name.clone()
    };

    // don't need to validate the same name again
    if wildcard == *query.name() {
        // this was validated by the nsec coverage over the query.name()
        true
    } else {
        // this is the final check, return it's value
        //  if there is wildcard coverage, we're good.
        verify_nsec_coverage(&wildcard)
    }
}
