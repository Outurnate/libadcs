use reqwest::Url;
use x509_certificate::rfc2986::CertificationRequest;

use crate::{soap::{SoapClient, HeaderBuilder, SoapHttpError}, soap_operations::{xcep::{GetPoliciesRequest, GetPoliciesResponse, CertificateAuthorityEndpoints, ClientAuthentication}, wstrust::{RequestSecurityToken, RequestSecurityTokenResponseCollection}}, client::{Policy, EnrollmentResponse, EnrollmentService, PolicyClient, EnrollmentClient}, AdcsError};

pub fn get_policy(endpoint: &Url) -> Result<Policy, ()>
{
  todo!()
}

pub struct HttpPolicyClient
{
  endpoint: Url
}

impl HttpPolicyClient
{
  pub fn new(endpoint: Url) -> Self
  {
    Self
    {
      endpoint
    }
  }

  fn get_policy(&self) -> Result<Policy, SoapHttpError>
  {
    let header = HeaderBuilder::default()
      .to(self.endpoint.to_string())
      .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies")
      .build()?;
    let client = SoapClient::new();
    let response: GetPoliciesResponse = client.invoke(&header, &GetPoliciesRequest::default())?;
    Ok(response.into_policy())
  }
}

pub struct HttpEnrollmentClient;

impl HttpEnrollmentClient
{
  fn submit(&self, request: &[u8], endpoint: Url) -> Result<EnrollmentResponse, AdcsError>
  {
    let client = SoapClient::new();
    let header = HeaderBuilder::default()
      .to(endpoint.as_str())
      .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep")
      .build()?;
    let response: RequestSecurityTokenResponseCollection = client.invoke(&header, &RequestSecurityToken::new(request, None))?;
    Ok(response)
  }
}