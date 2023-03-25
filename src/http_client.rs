use url::Url;

use crate::{CertificateClientImplementation, NamedCertificate};

pub struct HttpCertificateClient
{
}

impl CertificateClientImplementation for HttpCertificateClient
{
  fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>
  {
    todo!()
  }

  fn templates(&self) -> Vec<&'_ str>
  {
    todo!()
  }

  fn submit(&self, request: x509_certificate::rfc2986::CertificationRequest, template: &str) -> crate::Result<crate::EnrollmentResponse>
  {
    todo!()
  }
}

impl HttpCertificateClient
{
  pub fn new(endpoint: Url) -> Self
  {
    todo!()
  }
}