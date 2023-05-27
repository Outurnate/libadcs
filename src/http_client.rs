use reqwest::Url;

use crate::{soap::{SoapClient, HeaderBuilder, SoapHttpError}, soap_operations::{xcep::{GetPoliciesRequest, GetPoliciesResponse}, wstrust::{RequestSecurityToken, RequestSecurityTokenResponseCollection}}, client::{Policy, EnrollmentResponse}, NamedCertificate};

pub fn get_policy(root_certificates: Vec<NamedCertificate>, endpoint: &Url) -> Result<Policy, SoapHttpError>
{
  let header = HeaderBuilder::default()
    .to(endpoint.to_string())
    .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies")
    .build()?;
  let client = SoapClient::new();
  let response: GetPoliciesResponse = client.invoke(&header, &GetPoliciesRequest::default())?;
  Ok(response.into_policy())
}

fn submit(request: &[u8], endpoint: Url) -> Result<EnrollmentResponse, SoapHttpError>
{
  let client = SoapClient::new();
  let header = HeaderBuilder::default()
    .to(endpoint.to_string())
    .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep")
    .build()?;
  let response: RequestSecurityTokenResponseCollection = client.invoke(&header, &RequestSecurityToken::new(request, None))?;
  Ok(response.into())
}