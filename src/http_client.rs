use chrono::Local;
use reqwest::Url;

use crate::{soap::{SoapClient, HeaderBuilder, SoapError}, soap_operations::xcep::{GetPoliciesRequest, GetPoliciesResponse, CertificateAuthorityEndpoints}, client::{CertificateClientImplementation, Policy, EnrollmentResponse, EnrollmentService}, NamedCertificate};

pub struct HttpCertificateClient
{
  policy: Policy<CertificateAuthorityEndpoints>
}

impl CertificateClientImplementation for HttpCertificateClient
{
  type Endpoint = CertificateAuthorityEndpoints;
  type Error = SoapError;
  type Response = ();

  fn get_policy(&self) -> &Policy<Self::Endpoint>
  {
    &self.policy
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
  pub fn new(endpoint: Url, root_certificates: Vec<NamedCertificate>) -> Self
  {
    let header = HeaderBuilder::default()
      .action(endpoint.to_string())
      .build().unwrap();
    let client = SoapClient::new();
    let response: GetPoliciesResponse = client.invoke(&header, &GetPoliciesRequest::new(Local::now())).unwrap();

    Self { policy: response.into_policy(root_certificates) }
  }
}