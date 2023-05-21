use derive_builder::Builder;
use reqwest::Url;
use url::ParseError;
use yaserde_derive::{YaDeserialize, YaSerialize};
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Fault
{
  #[yaserde(rename = "Code", prefix = "soap")]
  code: FaultCode,

  #[yaserde(rename = "Reason", prefix = "soap")]
  reason: FaultReason,
  
  #[yaserde(rename = "Node", prefix = "soap")]
  node: Option<String>,
  
  #[yaserde(rename = "Role", prefix = "soap")]
  role: Option<String>,

  #[yaserde(rename = "Detail", prefix = "soap")]
  detail: Option<Detail>
}

impl Display for Fault
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result
  {
    f.write_fmt(format_args!("fault {}: {} (node={:?}, role={:?}, detail={:?})", self.code, self.reason, self.node, self.role, self.detail))
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultReason
{
  #[yaserde(rename = "Text", prefix = "soap")]
  texts: Vec<String>
}

impl Display for FaultReason
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result
  {
    f.write_str(&self.texts.join(", "))
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultCode
{
  #[yaserde(rename = "Value", prefix = "soap")]
  value: String,
  
  #[yaserde(rename = "Subcode", prefix = "soap")]
  subcode: Option<SubCode>
}

impl Display for FaultCode
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result
  {
    if let Some(ref subcode) = self.subcode
    {
      f.write_fmt(format_args!("{}.{}", self.value, subcode))
    }
    else
    {
      f.write_fmt(format_args!("{}", self.value))
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct SubCode
{
  #[yaserde(rename = "Value", prefix = "soap")]
  value: String
}

impl Display for SubCode
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result
  {
    f.write_str(&self.value)
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct Detail
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize, Builder)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
#[builder(setter(into), default)]
pub struct Header
{
  #[yaserde(rename = "ReplyTo", prefix = "wsa")]
  reply_to: Option<EndpointReference>,
  
  #[yaserde(rename = "From", prefix = "wsa")]
  from: Option<EndpointReference>,
  
  #[yaserde(rename = "FaultTo", prefix = "wsa")]
  fault_to: Option<EndpointReference>,
  
  #[yaserde(rename = "EndpointReference", prefix = "wsa")]
  endpoint_reference: Option<EndpointReference>,
  
  #[yaserde(rename = "To", prefix = "wsa")]
  to: Option<String>,
  
  #[yaserde(rename = "Action", prefix = "wsa")]
  action: String,
  
  #[yaserde(rename = "ProblemIRI", prefix = "wsa")]
  problem_iri: Option<String>,
  
  #[yaserde(rename = "MessageID", prefix = "wsa")]
  message_id: Option<String>,
  
  #[yaserde(rename = "RetryAfter", prefix = "wsa")]
  retry_after: Option<u64>,
  
  #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
  reference_parameters: Option<ReferenceParameters>,
  
  #[yaserde(rename = "Metadata", prefix = "wsa")]
  metadata: Option<MetadataType>,
  
  #[yaserde(rename = "RelatesTo", prefix = "wsa")]
  relates_to: Option<RelatesToType>,
  
  #[yaserde(rename = "ProblemHeaderstring", prefix = "wsa")]
  problem_headerstring: Option<String>,
  
  #[yaserde(rename = "ProblemAction", prefix = "wsa")]
  problem_action: Option<ProblemActionType>
}

impl Header
{
  pub fn get_action(&self) -> Result<Url, ParseError>
  {
    Url::parse(&self.action.as_str())
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize, Builder)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
#[builder(setter(into), default)]
pub struct EndpointReference
{
  #[yaserde(rename = "Address", prefix = "wsa")]
  address: String,

  #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
  reference_parameters: Option<ReferenceParameters>,

  #[yaserde(rename = "Metadata", prefix = "wsa")]
  metadata: Option<MetadataType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct ReferenceParameters
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct MetadataType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct RelatesToType
{
  #[yaserde(text)]
  content: String,

  #[yaserde(attribute, rename = "String")]
  relationship_type: Option <String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct ProblemActionType
{
  #[yaserde(rename = "Action", prefix = "wsa")]
  action: Option<String>,

  #[yaserde(rename = "SoapAction", prefix = "wsa")]
  soap_action: Option<String>
}