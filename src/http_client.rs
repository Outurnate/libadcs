use chrono::{Local, Months};
use reqwest::Url;

use crate::{soap::{SoapClient, HeaderBuilder, SoapError, SoapHttpError}, soap_operations::xcep::{GetPoliciesRequest, GetPoliciesResponse, CertificateAuthorityEndpoints}, client::{CertificateClientImplementation, Policy, EnrollmentResponse, EnrollmentService}, NamedCertificate};

pub struct HttpCertificateClient
{
  endpoint: Url
}

impl CertificateClientImplementation for HttpCertificateClient
{
  type Endpoint = CertificateAuthorityEndpoints;
  type Error = SoapHttpError;
  type Response = ();

  fn get_policy(&self) -> Result<Policy<Self::Endpoint>, Self::Error>
  {
    let header = HeaderBuilder::default()
      .to(self.endpoint.to_string())
      .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies")
      .build()?;
    let client = SoapClient::new();
    let response: GetPoliciesResponse = client.invoke(&header, &GetPoliciesRequest::new(Local::now().checked_sub_months(Months::new(24)).unwrap()))?;
    Ok(response.into_policy())
  }

  fn submit(&self, request: Vec<u8>, enrollment_service: &EnrollmentService<Self::Endpoint>) -> Result<Self::Response, Self::Error>
  {
    todo!()
  }

  fn decode_response(response: Self::Response) -> Result<EnrollmentResponse, crate::DecodeError>
  {
    todo!()
  }
}

impl HttpCertificateClient
{
  pub fn new(endpoint: Url) -> Self
  {
    Self
    {
      endpoint
    }
  }
}