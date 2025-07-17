# tls-listener

[![Apache 2 License](https://img.shields.io/badge/License-Apache--2.0-brightgreen)](https://www.apache.org/licenses/LICENSE-2.0)
[![Crate version](https://img.shields.io/crates/v/tls-listener)](https://crates.io/crates/tls-listener)
[![Docs](https://docs.rs/tls-listener/badge.svg)](https://docs.rs/tls-listener)
[![Build status](https://github.com/tmccombs/tls-listener/workflows/CI/badge.svg)](https://github.com/tmccombs/tls-listener/actions?query=workflow%3ACI)

This library is intended to automatically initiate a TLS connection
as for each new connection in a source of new streams (such as a listening
TCP or unix domain socket).

It can be used to easily create a `Stream` of TLS connections from a listening socket.

See examples for examples of usage.

You must enable either one of the `rustls` (more details below), `native-tls`, or `openssl`
features depending on which implementation you would like to use.

When enabling the `rustls` feature, the `rustls` crate will be added as a dependency along
with it's default [cryptography provider](https://docs.rs/rustls/latest/rustls/#cryptography-providers).
To avoid this behaviour and use other cryptography providers, the `rustls-core` feature can be used instead.
Additional feature flags for other [rustls built-in cryptography providers](https://docs.rs/rustls/latest/rustls/#built-in-providers) are also available:
`rustls-aws-lc` (default), `rustls-fips` and `rustls-ring`