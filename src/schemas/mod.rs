use std::io::Read;
use xml::{reader, writer};
use thiserror::Error;
use xmltree::{Element, ParseError};
use yaserde::{de, ser::{self, Serializer}};
use self::soap::{Header, Fault};

mod soap;
mod wstrust;
mod wsse;
mod wstep;
mod xcep;

#[derive(Error, Debug)]
pub enum Error
{
  #[error("invalid xml: {0}")]
  InvalidXml(#[from] ParseError),
  
  #[error("xml reader error: {0}")]
  Read(#[from] reader::Error),

  #[error("xml writer error: {0}")]
  Write(#[from] writer::Error),

  #[error("soap envelope has no body")]
  NoBody,

  #[error("invalid soap header: {0}")]
  InvalidHeader(String),

  #[error("invalid soap body: {0}")]
  InvalidBody(String),

  #[error("fault: {0}")]
  Fault(Box<Fault>)
}

trait ElementExt
{
  fn deserialize<T: yaserde::YaDeserialize>(&self, error_mapper: impl FnOnce(String) -> Error) -> Result<T, Error>;
}

impl ElementExt for Element
{
  fn deserialize<T: yaserde::YaDeserialize>(&self, error_mapper: impl FnOnce(String) -> Error) -> Result<T, Error>
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

pub trait SoapBody: yaserde::YaSerialize + yaserde::YaDeserialize + Default
{
  fn from_soap<R: Read>(reader: R) -> Result<(Option<Header>, Self), Error>;
  fn clone_to_soap(&self, header: &Header) -> Result<String, Error>;
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> SoapBody for T
{
  fn from_soap<R: Read>(reader: R) -> Result<(Option<Header>, Self), Error>
  {
    let tree = Element::parse(reader)?;
    let header = tree
      .get_child(("Header", "http://www.w3.org/2003/05/soap-envelope"))
      .map(|header| header.deserialize(Error::InvalidHeader))
      .transpose()?;
    if let Some(body) = tree.get_child(("Body", "http://www.w3.org/2003/05/soap-envelope"))
    {
      if let Some(fault) = body.get_child(("Fault", "http://www.w3.org/2003/05/soap-envelope"))
      {
        Err(Error::Fault(Box::new(fault.deserialize(Error::InvalidBody)?)))
      }
      else
      {
        Ok((header, body.deserialize(Error::InvalidBody)?))
      }
    }
    else
    {
      Err(Error::NoBody)
    }
  }

  fn clone_to_soap(&self, header: &Header) -> Result<String, Error>
  {
    let config = ser::Config { perform_indent: false, write_document_declaration: false, indent_string: None };
    let header = ser::to_string_with_config(header, &config).map_err(Error::InvalidHeader)?;
    let body = to_string_with_config_and_start(self, &config, "soap:Body".to_owned()).map_err(Error::InvalidBody)?;
    Ok(format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">{}{}</soap:Envelope>", header, body))
  }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests
{
  use uuid::Uuid;
  use crate::cmc::CmcMessage;
  use super::{soap::HeaderBuilder};
  use super::{soap::EndpointReferenceBuilder, wstrust::RequestSecurityToken};
  use super::{SoapBody, Error};

  #[test]
  fn fault()
  {
    let fault = include_str!("tests/fault.xml");
    if let Err(Error::Fault(fault)) = RequestSecurityToken::from_soap(fault.as_bytes())
    {
      assert_eq!(fault.to_string(), "fault env:Sender: Message does not have necessary info (node=None, role=Some(\"http://gizmos.com/order\"), detail=Some(Detail))".to_owned());
    }
    else
    {
      panic!();
    }
  }

  #[test]
  fn round_trip()
  {
    let header = HeaderBuilder::default()
      .reply_to(EndpointReferenceBuilder::default()
        .address("http://www.w3.org/2005/08/addressing/anonymous".to_owned())
        .build().expect("error building endpoint reference"))
      .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep".to_owned())
      .message_id(format!("urn:uuid:{}", Uuid::new_v4()))
      .build().expect("error building header");
    let body = RequestSecurityToken::new(CmcMessage(vec![0]), Some("7777".to_owned()));
    let envelope = body.clone_to_soap(&header).expect("failed to create soap envelope");

    let (new_header, new_body) = RequestSecurityToken::from_soap(envelope.as_bytes()).expect("failed to reparse soap envelope");

    assert_eq!(header, new_header.expect("header lost in round trip"));
    assert_eq!(body, new_body);
  }

  #[test]
  fn parse_known()
  {
    let known = include_str!("tests/wstep.xml");
    RequestSecurityToken::from_soap(known.as_bytes()).expect("failed to parse known good soap message");
  }
}