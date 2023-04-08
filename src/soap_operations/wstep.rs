use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wstep", namespace = "wstep: http://schemas.microsoft.com/windows/pki/2009/01/enrollment")]
struct CertificateEnrollmentWsDetailType
{
  #[yaserde(rename = "BinaryResponse", prefix = "wstep")]
  binary_response: Option<String>,

  #[yaserde(rename = "ErrorCode", prefix = "wstep")]
  error_code: Option<i32>,

  #[yaserde(rename = "InvalidRequest", prefix = "wstep")]
  invalid_request: Option<bool>,

  #[yaserde(rename = "RequestID", prefix = "wstep")]
  request_id: Option<String>
}