use chrono::Local;
use reqwest::Url;

use crate::{soap::{SoapClient, HeaderBuilder}, soap_operations::xcep::{GetPoliciesRequest, GetPoliciesResponse, CertificateAuthorityEndpoints}, client::{CertificateClientImplementation, Policy, EnrollmentResponse}};

pub struct HttpCertificateClient
{
  policies: GetPoliciesResponse
}

impl CertificateClientImplementation for HttpCertificateClient
{
  type Endpoint = CertificateAuthorityEndpoints;

  fn submit(&self, request: x509_certificate::rfc2986::CertificationRequest, template: &str) -> crate::Result<EnrollmentResponse>
  {
    todo!()
  }

  fn get_policy(&self) -> &Policy<Self::Endpoint>
  {
    todo!()
  }
}

impl HttpCertificateClient
{
  pub fn new(endpoint: Url) -> Self
  {
    let header = HeaderBuilder::default()
      .action(endpoint.to_string())
      .build().unwrap();
    let client = SoapClient::new();
    let policies = client.invoke(&header, &GetPoliciesRequest::new(Local::now())).unwrap();

    Self { policies }
  }
}