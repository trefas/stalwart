/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod address;
pub mod content_type;
pub mod date;
pub mod message_id;
pub mod raw;
pub mod text;
pub mod url;

use std::io::{self, Write};

use self::{
    address::Address, content_type::ContentType, date::Date, message_id::MessageId, raw::Raw,
    text::Text, url::URL,
};

pub trait Header {
    fn write_header(&self, output: impl Write, bytes_written: usize) -> io::Result<usize>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeaderType<'x> {
    Address(Address<'x>),
    Date(Date),
    MessageId(MessageId<'x>),
    Raw(Raw<'x>),
    Text(Text<'x>),
    URL(URL<'x>),
    ContentType(ContentType<'x>),
}

impl<'x> From<Address<'x>> for HeaderType<'x> {
    fn from(value: Address<'x>) -> Self {
        HeaderType::Address(value)
    }
}

impl<'x> From<ContentType<'x>> for HeaderType<'x> {
    fn from(value: ContentType<'x>) -> Self {
        HeaderType::ContentType(value)
    }
}

impl From<Date> for HeaderType<'_> {
    fn from(value: Date) -> Self {
        HeaderType::Date(value)
    }
}
impl<'x> From<MessageId<'x>> for HeaderType<'x> {
    fn from(value: MessageId<'x>) -> Self {
        HeaderType::MessageId(value)
    }
}
impl<'x> From<Raw<'x>> for HeaderType<'x> {
    fn from(value: Raw<'x>) -> Self {
        HeaderType::Raw(value)
    }
}
impl<'x> From<Text<'x>> for HeaderType<'x> {
    fn from(value: Text<'x>) -> Self {
        HeaderType::Text(value)
    }
}

impl<'x> From<URL<'x>> for HeaderType<'x> {
    fn from(value: URL<'x>) -> Self {
        HeaderType::URL(value)
    }
}

impl Header for HeaderType<'_> {
    fn write_header(&self, output: impl Write, bytes_written: usize) -> io::Result<usize> {
        match self {
            HeaderType::Address(value) => value.write_header(output, bytes_written),
            HeaderType::Date(value) => value.write_header(output, bytes_written),
            HeaderType::MessageId(value) => value.write_header(output, bytes_written),
            HeaderType::Raw(value) => value.write_header(output, bytes_written),
            HeaderType::Text(value) => value.write_header(output, bytes_written),
            HeaderType::URL(value) => value.write_header(output, bytes_written),
            HeaderType::ContentType(value) => value.write_header(output, bytes_written),
        }
    }
}

impl HeaderType<'_> {
    pub fn as_content_type(&self) -> Option<&ContentType<'_>> {
        match self {
            HeaderType::ContentType(value) => Some(value),
            _ => None,
        }
    }
}
