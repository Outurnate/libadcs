use libadcs::{CertificateServicesClient, AdcsError};
use url::Url;
use x509_certificate::rfc2986::CertificationRequest;
use crate::{EnrollmentResponse, Error, RootCertificates, Environment};

pub struct Operations
{
  client: CertificateServicesClient
}

impl Operations
{
  pub fn new(env: Environment) -> Result<Self, Error>
  {
    let client = CertificateServicesClient::new(env.realm, Url::parse(&env.endpoint).unwrap(), false)?;
    Ok(Self { client })
  }

  pub fn submit(self, csr: CertificationRequest, ca_profile: String) -> Result<EnrollmentResponse, Error>
  {
    Ok(self.client.submit(csr, &ca_profile)?)
  }

  pub fn poll(self, ca_cookie: String) -> Result<EnrollmentResponse, Error>
  {
    todo!()
  }

  pub fn identify(self) -> Result<String, Error>
  {
    todo!()
  }

  pub fn fetch_roots(self) -> Result<RootCertificates, Error>
  {
    let roots = self.client.root_certificates();
    let chain = self.client.chain_certificates();
    Ok(RootCertificates
    {
      primary_root_certificate: roots.first().map(|cert| (*cert).clone()),
      supplementary_root_certificates: if roots.len() > 1
      {
        roots.as_slice()[1..].iter().map(|cert| (*cert).clone()).collect()
      }
      else
      {
        vec![]
      },
      chain_certificates: chain.into_iter().cloned().collect()
    })
  }

  pub fn new_or_renew_requirements(self) -> Result<Vec<String>, Error>
  {
    Ok(vec![String::from("")])
  }

  pub fn supported_templates(self) -> Result<Vec<String>, Error>
  {
    Ok(self.client.template_names().into_iter().map(|template| template.to_string()).collect())
  }
}