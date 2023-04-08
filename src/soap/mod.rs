use std::io::Read;
use xml::{reader, writer};
use thiserror::Error;
use xmltree::{Element, ParseError};
use yaserde::ser;
use self::schema::{Fault, Header};
use self::xml_helpers::{ElementExt, to_string_with_config_and_start};

pub mod schema;
mod http;
mod xml_helpers;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

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