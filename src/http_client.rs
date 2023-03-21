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
}

impl HttpCertificateClient
{
  pub fn new(endpoint: Url) -> Self
  {
    todo!()
  }
}