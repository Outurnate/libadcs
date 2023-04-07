use yaserde_derive::{YaDeserialize, YaSerialize};
use base64::{Engine as _, engine::general_purpose};

use crate::cmc::CmcMessage;

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsse", namespace = "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
pub struct BinarySecurityTokenType
{
  content: EncodedString,
    
  #[yaserde(attribute, rename = "ValueType")]
  value_type: Option<String>
}

impl From<CmcMessage> for BinarySecurityTokenType
{
  fn from(value: CmcMessage) -> Self
  {
    Self
    {
      content: value.0.into(),
      value_type: Some("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7".to_owned())
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsse", namespace = "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
struct EncodedString
{
  content: String,

  #[yaserde(attribute, rename = "EncodingType")]
  encoding_type: Option<String>
}

impl<T: AsRef<[u8]>> From<T> for EncodedString
{
  fn from(value: T) -> Self
  {
    Self
    {
      content: general_purpose::STANDARD.encode(value),
      encoding_type: Some("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary".to_owned())
    }
  }
}