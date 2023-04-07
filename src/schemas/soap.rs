use uuid::Uuid;
use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::cmc::CmcMessage;

use super::{wstrust::{RequestSecurityTokenType, RequestSecurityTokenResponseCollectionType}, xcep::{GetPoliciesType, GetPoliciesResponseType}};

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct EnvelopeType
{
  #[yaserde(rename = "Header", prefix = "soap")]
  header: HeaderType,

  #[yaserde(rename = "Body", prefix = "soap")]
  body: BodyType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
enum BodyType
{
  #[yaserde(rename = "Fault", prefix = "soap")]
  Fault(FaultType),

  #[yaserde(rename = "NotUnderstood", prefix = "soap")]
  NotUnderstood(NotUnderstoodType),

  #[yaserde(rename = "Upgrade", prefix = "soap")]
  Upgrade(UpgradeType),

  #[yaserde(rename = "RequestSecurityToken", prefix = "wst")]
  RequestSecurityToken(RequestSecurityTokenType),

  #[yaserde(rename = "RequestSecurityTokenResponseCollection", prefix = "wst")]
  RequestSecurityTokenResponseCollection(RequestSecurityTokenResponseCollectionType),

  #[yaserde(rename = "GetPolicies", prefix = "xcep")]
  GetPolicies(GetPoliciesType),

  #[yaserde(rename = "GetPoliciesResponse", prefix = "xcep")]
  GetPoliciesResponse(GetPoliciesResponseType),

  #[default]
  None
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultType
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

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultReason
{
  #[yaserde(rename = "Text", prefix = "soap")]
  texts: Vec<String>
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

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct SubCode
{
  #[yaserde(rename = "Value", prefix = "soap")]
  value: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct Detail
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct NotUnderstoodType
{
  #[yaserde(attribute)]
  qname: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct SupportedEnvType
{
  #[yaserde(attribute)]
  qname: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct UpgradeType
{
  #[yaserde(rename = "SupportedEnvelope", prefix = "soap")]
  supported_envelopes: Vec<SupportedEnvType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct HeaderType
{
  #[yaserde(rename = "ReplyTo", prefix = "wsa")]
  reply_to: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "From", prefix = "wsa")]
  from: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "FaultTo", prefix = "wsa")]
  fault_to: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "EndpointReference", prefix = "wsa")]
  endpoint_reference: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "To", prefix = "wsa")]
  to: Option<String>,
  
  #[yaserde(rename = "Action", prefix = "wsa")]
  action: Option<String>,
  
  #[yaserde(rename = "ProblemIRI", prefix = "wsa")]
  problem_iri: Option<String>,
  
  #[yaserde(rename = "MessageID", prefix = "wsa")]
  message_id: Option<String>,
  
  #[yaserde(rename = "RetryAfter", prefix = "wsa")]
  retry_after: Option<u64>,
  
  #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
  reference_parameters: Option<ReferenceParametersType>,
  
  #[yaserde(rename = "Metadata", prefix = "wsa")]
  metadata: Option<MetadataType>,
  
  #[yaserde(rename = "RelatesTo", prefix = "wsa")]
  relates_to: Option<RelatesToType>,
  
  #[yaserde(rename = "ProblemHeaderstring", prefix = "wsa")]
  problem_headerstring: Option<String>,
  
  #[yaserde(rename = "ProblemAction", prefix = "wsa")]
  problem_action: Option<ProblemActionType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct EndpointReferenceType
{
  #[yaserde(rename = "Address", prefix = "wsa")]
  address: String,

  #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
  reference_parameters: Option<ReferenceParametersType>,

  #[yaserde(rename = "Metadata", prefix = "wsa")]
  metadata: Option<MetadataType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct ReferenceParametersType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct MetadataType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct RelatesToType
{
  #[yaserde(text)]
  content: String,

  #[yaserde(attribute, rename = "String")]
  relationship_type: Option <String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct ProblemActionType
{
  #[yaserde(rename = "Action", prefix = "wsa")]
  action: Option<String>,

  #[yaserde(rename = "SoapAction", prefix = "wsa")]
  soap_action: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Envelope
{
  #[yaserde(flatten)]
  content: EnvelopeType
}

impl Envelope
{
  fn request_security_token(message: CmcMessage, request_id: String) -> Self
  {
    Self
    {
      content: EnvelopeType
      {
        header: HeaderType
        {
          reply_to: Some(EndpointReferenceType
            {
              address: "http://www.w3.org/2005/08/addressing/anonymous".to_owned(),
              ..Default::default()
            }),
          action: Some("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep".to_owned()),
          message_id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
          ..Default::default()
        },
        body: BodyType::RequestSecurityToken(RequestSecurityTokenType::new(message, request_id))
      }
    }
  }

  /*fn get_policies(t: GetPoliciesType) -> Self
  {
  }*/
}