/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#[forbid(unsafe_code)]
pub mod encoders;
pub mod headers;
pub mod mime;

use std::{
    borrow::Cow,
    io::{self, Write},
};

use headers::{
    address::Address,
    content_type::ContentType,
    date::Date,
    message_id::{generate_message_id_header, MessageId},
    text::Text,
    Header, HeaderType,
};
use mime::{BodyPart, MimePart};

/// Builds an RFC5322 compliant MIME email message.
#[derive(Clone, Debug)]
pub struct MessageBuilder<'x> {
    pub headers: Vec<(Cow<'x, str>, HeaderType<'x>)>,
    pub html_body: Option<MimePart<'x>>,
    pub text_body: Option<MimePart<'x>>,
    pub attachments: Option<Vec<MimePart<'x>>>,
    pub body: Option<MimePart<'x>>,
}

impl Default for MessageBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'x> MessageBuilder<'x> {
    /// Create a new MessageBuilder.
    pub fn new() -> Self {
        MessageBuilder {
            headers: Vec::new(),
            html_body: None,
            text_body: None,
            attachments: None,
            body: None,
        }
    }

    /// Set the Message-ID header. If no Message-ID header is set, one will be
    /// generated automatically.
    pub fn message_id(self, value: impl Into<MessageId<'x>>) -> Self {
        self.header("Message-ID", value.into())
    }

    /// Set the In-Reply-To header.
    pub fn in_reply_to(self, value: impl Into<MessageId<'x>>) -> Self {
        self.header("In-Reply-To", value.into())
    }

    /// Set the References header.
    pub fn references(self, value: impl Into<MessageId<'x>>) -> Self {
        self.header("References", value.into())
    }

    /// Set the Sender header.
    pub fn sender(self, value: impl Into<Address<'x>>) -> Self {
        self.header("Sender", value.into())
    }

    /// Set the From header.
    pub fn from(self, value: impl Into<Address<'x>>) -> Self {
        self.header("From", value.into())
    }

    /// Set the To header.
    pub fn to(self, value: impl Into<Address<'x>>) -> Self {
        self.header("To", value.into())
    }

    /// Set the Cc header.
    pub fn cc(self, value: impl Into<Address<'x>>) -> Self {
        self.header("Cc", value.into())
    }

    /// Set the Bcc header.
    pub fn bcc(self, value: impl Into<Address<'x>>) -> Self {
        self.header("Bcc", value.into())
    }

    /// Set the Reply-To header.
    pub fn reply_to(self, value: impl Into<Address<'x>>) -> Self {
        self.header("Reply-To", value.into())
    }

    /// Set the Subject header.
    pub fn subject(self, value: impl Into<Text<'x>>) -> Self {
        self.header("Subject", value.into())
    }

    /// Set the Date header. If no Date header is set, one will be generated
    /// automatically.
    pub fn date(self, value: impl Into<Date>) -> Self {
        self.header("Date", value.into())
    }

    /// Add a custom header.
    pub fn header(
        mut self,
        header: impl Into<Cow<'x, str>>,
        value: impl Into<HeaderType<'x>>,
    ) -> Self {
        self.headers.push((header.into(), value.into()));
        self
    }

    /// Set custom headers.
    pub fn headers<T, U, V>(mut self, header: T, values: U) -> Self
    where
        T: Into<Cow<'x, str>>,
        U: IntoIterator<Item = V>,
        V: Into<HeaderType<'x>>,
    {
        let header = header.into();

        for value in values {
            self.headers.push((header.clone(), value.into()));
        }

        self
    }

    /// Set the plain text body of the message. Note that only one plain text body
    /// per message can be set using this function.
    /// To build more complex MIME body structures, use the `body` method instead.
    pub fn text_body(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.text_body = Some(MimePart::new("text/plain", BodyPart::Text(value.into())));
        self
    }

    /// Set the HTML body of the message. Note that only one HTML body
    /// per message can be set using this function.
    /// To build more complex MIME body structures, use the `body` method instead.
    pub fn html_body(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.html_body = Some(MimePart::new("text/html", BodyPart::Text(value.into())));
        self
    }

    /// Add a binary attachment to the message.
    pub fn attachment(
        mut self,
        content_type: impl Into<ContentType<'x>>,
        filename: impl Into<Cow<'x, str>>,
        value: impl Into<BodyPart<'x>>,
    ) -> Self {
        self.attachments
            .get_or_insert_with(Vec::new)
            .push(MimePart::new(content_type, value).attachment(filename));
        self
    }

    /// Add an inline binary to the message.
    pub fn inline(
        mut self,
        content_type: impl Into<ContentType<'x>>,
        cid: impl Into<Cow<'x, str>>,
        value: impl Into<BodyPart<'x>>,
    ) -> Self {
        self.attachments
            .get_or_insert_with(Vec::new)
            .push(MimePart::new(content_type, value).inline().cid(cid));
        self
    }

    /// Set a custom MIME body structure.
    pub fn body(mut self, value: MimePart<'x>) -> Self {
        self.body = Some(value);
        self
    }

    /// Build the message.
    pub fn write_to(self, mut output: impl Write) -> io::Result<()> {
        let mut has_date = false;
        let mut has_message_id = false;
        let mut has_mime_version = false;

        for (header_name, header_value) in &self.headers {
            if !has_date && header_name == "Date" {
                has_date = true;
            } else if !has_message_id && header_name == "Message-ID" {
                has_message_id = true;
            } else if !has_mime_version && header_name == "MIME-Version" {
                has_mime_version = true;
            }

            output.write_all(header_name.as_bytes())?;
            output.write_all(b": ")?;
            header_value.write_header(&mut output, header_name.len() + 2)?;
        }

        if !has_message_id {
            output.write_all(b"Message-ID: ")?;

            #[cfg(feature = "gethostname")]
            generate_message_id_header(
                &mut output,
                gethostname::gethostname().to_str().unwrap_or("localhost"),
            )?;

            #[cfg(not(feature = "gethostname"))]
            generate_message_id_header(&mut output, "localhost")?;

            output.write_all(b"\r\n")?;
        }

        if !has_date {
            output.write_all(b"Date: ")?;
            output.write_all(Date::now().to_rfc822().as_bytes())?;
            output.write_all(b"\r\n")?;
        }

        if !has_mime_version {
            output.write_all(b"MIME-Version: 1.0\r\n")?;
        }

        self.write_body(output)
    }

    /// Write the message body without headers.
    pub fn write_body(self, output: impl Write) -> io::Result<()> {
        (if let Some(body) = self.body {
            body
        } else {
            match (self.text_body, self.html_body, self.attachments) {
                (Some(text), Some(html), Some(attachments)) => {
                    let mut parts = Vec::with_capacity(attachments.len() + 1);
                    parts.push(MimePart::new("multipart/alternative", vec![text, html]));
                    parts.extend(attachments);

                    MimePart::new("multipart/mixed", parts)
                }
                (Some(text), Some(html), None) => {
                    MimePart::new("multipart/alternative", vec![text, html])
                }
                (Some(text), None, Some(attachments)) => {
                    let mut parts = Vec::with_capacity(attachments.len() + 1);
                    parts.push(text);
                    parts.extend(attachments);
                    MimePart::new("multipart/mixed", parts)
                }
                (Some(text), None, None) => text,
                (None, Some(html), Some(attachments)) => {
                    let mut parts = Vec::with_capacity(attachments.len() + 1);
                    parts.push(html);
                    parts.extend(attachments);
                    MimePart::new("multipart/mixed", parts)
                }
                (None, Some(html), None) => html,
                (None, None, Some(attachments)) => MimePart::new("multipart/mixed", attachments),
                (None, None, None) => MimePart::new("text/plain", "\n"),
            }
        })
        .write_part(output)?;

        Ok(())
    }

    /// Build message to a Vec<u8>.
    pub fn write_to_vec(self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        self.write_to(&mut output)?;
        Ok(output)
    }

    /// Build message to a String.
    pub fn write_to_string(self) -> io::Result<String> {
        let mut output = Vec::new();
        self.write_to(&mut output)?;
        String::from_utf8(output).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

#[cfg(test)]
mod tests {

    use mail_parser::MessageParser;

    use crate::{
        headers::{address::Address, url::URL},
        mime::MimePart,
        MessageBuilder,
    };

    #[test]
    fn build_nested_message() {
        let output = MessageBuilder::new()
            .from(Address::new_address("John Doe".into(), "john@doe.com"))
            .to(Address::new_address("Jane Doe".into(), "jane@doe.com"))
            .subject("RFC 8621 Section 4.1.4 test")
            .body(MimePart::new(
                "multipart/mixed",
                vec![
                    MimePart::new("text/plain", "Part A contents go here...").inline(),
                    MimePart::new(
                        "multipart/mixed",
                        vec![
                            MimePart::new(
                                "multipart/alternative",
                                vec![
                                    MimePart::new(
                                        "multipart/mixed",
                                        vec![
                                            MimePart::new(
                                                "text/plain",
                                                "Part B contents go here...",
                                            )
                                            .inline(),
                                            MimePart::new(
                                                "image/jpeg",
                                                "Part C contents go here...".as_bytes(),
                                            )
                                            .inline(),
                                            MimePart::new(
                                                "text/plain",
                                                "Part D contents go here...",
                                            )
                                            .inline(),
                                        ],
                                    ),
                                    MimePart::new(
                                        "multipart/related",
                                        vec![
                                            MimePart::new(
                                                "text/html",
                                                "Part E contents go here...",
                                            )
                                            .inline(),
                                            MimePart::new(
                                                "image/jpeg",
                                                "Part F contents go here...".as_bytes(),
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            MimePart::new("image/jpeg", "Part G contents go here...".as_bytes())
                                .attachment("image_G.jpg"),
                            MimePart::new(
                                "application/x-excel",
                                "Part H contents go here...".as_bytes(),
                            ),
                            MimePart::new(
                                "x-message/rfc822",
                                "Part J contents go here...".as_bytes(),
                            ),
                        ],
                    ),
                    MimePart::new("text/plain", "Part K contents go here...").inline(),
                ],
            ))
            .write_to_vec()
            .unwrap();
        MessageParser::new().parse(&output).unwrap();
        //fs::write("test.yaml", &serde_yaml::to_string(&message).unwrap()).unwrap();
    }

    #[test]
    fn build_message() {
        let output = MessageBuilder::new()
            .from(("John Doe", "john@doe.com"))
            .to(vec![
                ("Antoine de Saint-Exupéry", "antoine@exupery.com"),
                ("안녕하세요 세계", "test@test.com"),
                ("Xin chào", "addr@addr.com"),
            ])
            .bcc(vec![
                (
                    "Привет, мир",
                    vec![
                        ("ASCII recipient", "addr1@addr7.com"),
                        ("ハロー・ワールド", "addr2@addr6.com"),
                        ("áéíóú", "addr3@addr5.com"),
                        ("Γειά σου Κόσμε", "addr4@addr4.com"),
                    ],
                ),
                (
                    "Hello world",
                    vec![
                        ("שלום עולם", "addr5@addr3.com"),
                        ("¡El ñandú comió ñoquis!", "addr6@addr2.com"),
                        ("Recipient", "addr7@addr1.com"),
                    ],
                ),
            ])
            .header("List-Archive", URL::new("http://example.com/archive"))
            .subject("Hello world!")
            .text_body("Hello, world!\n".repeat(20))
            .html_body("<p>¡Hola Mundo!</p>".repeat(20))
            .inline("image/png", "cid:image", [0, 1, 2, 3, 4, 5].as_ref())
            .attachment("text/plain", "my fíle.txt", "안녕하세요 세계".repeat(20))
            .attachment(
                "text/plain",
                "ハロー・ワールド",
                "ハロー・ワールド".repeat(20).into_bytes(),
            )
            .write_to_vec()
            .unwrap();
        MessageParser::new().parse(&output).unwrap();
    }
}
