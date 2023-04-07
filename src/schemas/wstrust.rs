use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::cmc::CmcMessage;

use super::wsse::BinarySecurityTokenType;

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
pub struct RequestSecurityTokenType
{
  #[yaserde(rename = "TokenType", prefix = "wst")]
  token_type: String,

  #[yaserde(rename = "RequestType", prefix = "wst")]
  request_type: String,

  #[yaserde(rename = "BinarySecurityToken", prefix = "wst")]
  binary_security_token: BinarySecurityTokenType,

  #[yaserde(rename = "RequestID", prefix = "wst")]
  request_id: String,

  #[yaserde(attribute, rename = "Context")]
  context: Option<String>
}

impl RequestSecurityTokenType
{
  pub fn new(message: CmcMessage, request_id: String) -> Self
  {
    Self
    {
      token_type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3".to_owned(),
      request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_owned(),
      binary_security_token: message.into(),
      request_id,
      context: None
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
struct RequestSecurityTokenResponseType
{
  #[yaserde(rename = "TokenType", prefix = "wst")]
  token_type: String,

  #[yaserde(rename = "DispositionMessage", prefix = "wst")]
  disposition_message: String,

  #[yaserde(rename = "BinarySecurityToken", prefix = "wst")]
  binary_security_token: BinarySecurityTokenType,

  #[yaserde(rename = "RequestedSecurityToken", prefix = "wst")]
  requested_security_token: RequestedSecurityTokenType,

  #[yaserde(rename = "RequestID", prefix = "wst")]
  request_id: String,

  #[yaserde(attribute, rename = "Context")]
  context: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
struct RequestedSecurityTokenType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
pub struct RequestSecurityTokenResponseCollectionType
{
  #[yaserde(rename = "RequestSecurityTokenResponse", prefix = "wst")]
  request_security_token_responses: Vec<RequestSecurityTokenResponseType>
}