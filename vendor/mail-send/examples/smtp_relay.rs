/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_builder::MessageBuilder;
use mail_send::SmtpClientBuilder;

#[tokio::main]
async fn main() {
    // Build a simple text message with a single attachment
    // More examples of how to build messages available at
    // https://github.com/stalwartlabs/mail-builder/tree/main/examples
    let message = MessageBuilder::new()
        .from(("John Doe", "john@example.com"))
        .to("jane@example.com")
        .subject("Hello, world!")
        .text_body("Hello, world!")
        .attachment("image/png", "kittens.png", [1, 2, 3, 4].as_ref());

    // Connect to an SMTP relay server.
    // The library will upgrade the connection to TLS if the server supports it.
    SmtpClientBuilder::new("mail.smtp2go.com", 2525)
        .implicit_tls(false)
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();
}
