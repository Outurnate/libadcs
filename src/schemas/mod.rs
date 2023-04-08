use std::io::Read;
use xml::{reader, writer};
use thiserror::Error;
use xmltree::{Element, ParseError, XMLNode};
use yaserde::{de, ser};
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

  #[error("soap envelope has no header")]
  NoHeader,

  #[error("soap envelope has no body")]
  NoBody,

  #[error("invalid soap header: {0}")]
  InvalidHeader(String),

  #[error("invalid soap body: {0}")]
  InvalidBody(String),

  #[error("fault: {0}")]
  Fault(Box<Fault>)
}

fn deserialize_from_element<T: yaserde::YaDeserialize>(element: &Element, local_name: impl AsRef<str>, namespace: impl AsRef<str>, error_mapper: impl FnOnce(String) -> Error) -> Result<Option<T>, Error>
{
  element.get_child((local_name.as_ref(), namespace.as_ref())).map(|element|
  {
    let mut buffer = Vec::new();
    element.write(&mut buffer)?;
    de::from_reader(buffer.as_slice()).map_err(error_mapper)
  }).transpose()
}

pub trait SoapBody: yaserde::YaSerialize + yaserde::YaDeserialize + Default
{
  fn from_soap<R: Read>(reader: R) -> Result<(Header, Self), Error>;
  fn clone_to_soap(&self, header: &Header) -> Result<String, Error>;
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> SoapBody for T
{
  fn from_soap<R: Read>(reader: R) -> Result<(Header, Self), Error>
  {
    let tree = Element::parse(reader)?;
    let header = deserialize_from_element(&tree, "Header", "http://www.w3.org/2003/05/soap-envelope", Error::InvalidHeader)
      .map(|v| match v
      {
        Some(v) => Ok(v),
        None => Err(Error::NoHeader),
      })??;
    if let Some(body) = tree.get_child(("Body", "http://www.w3.org/2003/05/soap-envelope"))
    {
      if let Some(fault) = deserialize_from_element(&tree, "Fault", "http://www.w3.org/2003/05/soap-envelope", Error::InvalidBody)?
      {
        Err(Error::Fault(Box::new(fault)))
      }
      else
      {
        let mut body_contents = Vec::new();
        for child in &body.children
        {
          if let XMLNode::Element(child) = child
          {
            child.write(&mut body_contents)?;
          }
        }
        match de::from_reader(body_contents.as_slice())
        {
          Ok(body) => Ok((header, body)),
          Err(msg) => Err(Error::InvalidBody(msg))
        }
      }
    }
    else
    {
      Err(Error::NoBody)
    }
  }

  fn clone_to_soap(&self, header: &Header) -> Result<String, Error>
  {
    let pre = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header>";
    let sep = "</soap:Header><soap:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">";
    let post = "</soap:Body></soap:Envelope>";
    let config = ser::Config { perform_indent: false, write_document_declaration: false, indent_string: None };
    let header = ser::to_string_with_config(header, &config).map_err(Error::InvalidHeader)?;
    let body = ser::to_string_with_config(self, &config).map_err(Error::InvalidBody)?;
    Ok(pre.to_owned() + &header + sep + &body + post)
  }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests
{
  use uuid::Uuid;
  use crate::{schemas::soap::HeaderBuilder, cmc::CmcMessage};
  use super::{soap::EndpointReferenceBuilder, wstrust::RequestSecurityToken};
  use super::SoapBody;

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
    let body = RequestSecurityToken::new(CmcMessage(vec![0]), None);
    let envelope = body.clone_to_soap(&header).expect("failed to create soap envelope");
    println!("{}", envelope);

    let (new_header, new_body) = RequestSecurityToken::from_soap(envelope.as_bytes()).expect("failed to reparse soap envelope");

    assert_eq!(header, new_header);
    assert_eq!(body, new_body);
  }
}