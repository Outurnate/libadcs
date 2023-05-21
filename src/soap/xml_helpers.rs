use std::{io::{Read, Write}, borrow::Borrow};

use base64::{engine::general_purpose, Engine};
use bcder::Oid;
use bytes::Bytes;
use tracing::instrument;
use xml::{reader, writer, attribute::OwnedAttribute};
use xmltree::{Element, Namespace};
use yaserde::{de::{self, Deserializer}, ser::{self, Serializer}, YaDeserialize, YaSerialize};
use crate::cmc::OidExt;
use super::SoapError;

pub trait ElementExt
{
  fn deserialize<T: yaserde::YaDeserialize>(&self, error_mapper: impl FnOnce(String) -> SoapError) -> Result<T, SoapError>;
}

impl ElementExt for Element
{
  fn deserialize<T: yaserde::YaDeserialize>(&self, error_mapper: impl FnOnce(String) -> SoapError) -> Result<T, SoapError>
  {
    let mut buffer = Vec::new();
    self.write(&mut buffer)?;
    de::from_reader(buffer.as_slice()).map_err(error_mapper)
  }
}

pub fn to_string_with_config_and_start<T: yaserde::YaSerialize>(model: &T, config: &ser::Config, start_event_name: String) -> Result<String, String>
{
  let mut buf = Vec::new();
  let mut serializer = Serializer::new_from_writer(&mut buf, config);
  serializer.set_start_event_name(Some(start_event_name));
  yaserde::YaSerialize::serialize(model, &mut serializer)?;
  let data = std::str::from_utf8(buf.as_slice()).expect("Found invalid UTF-8");
  Ok(data.into())
}