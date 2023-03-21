mod ldap;
mod sddl;
mod ldap_client;
mod http_client;
mod cmc;
mod rfc5272;

use std::fmt::Display;
use http_client::HttpCertificateClient;
use ldap::LdapManager;
use ldap3::LdapError;
use ldap_client::LdapCertificateClient;
use thiserror::Error;
use tokio::runtime::Runtime;
use url::Url;
use x509_certificate::X509Certificate;

#[derive(Debug, Clone)]
pub struct NamedCertificate
{
  nickname: String,
  certificate: X509Certificate
}

impl Display for NamedCertificate
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    match self.certificate.encode_pem()
    {
      Ok(certificate) => f.write_fmt(format_args!("{}\n{}\n", self.nickname, certificate)),
      Err(_) => Err(std::fmt::Error)
    }
  }
}

#[derive(Error, Debug)]
pub enum AdcsError
{
  #[error("ldap connection error: {0}")]
  LdapConnectionFailed(#[from] LdapError),
  #[error("unknown endpoint scheme: {0}")]
  UnknownEndpointScheme(String)
}

type Result<T> = std::result::Result<T, AdcsError>;

pub struct CertificateServicesClient
{
  root_certificates: Vec<NamedCertificate>,
  implementation: Box<dyn CertificateClientImplementation>
}

impl CertificateServicesClient
{
  pub fn new(forest: String, endpoint: Url, tls: bool) -> Result<Self>
  {
    let rt  = Runtime::new().unwrap();
    let mut ldap = LdapManager::new(forest, tls, &rt);
    let root_certificates = ldap.get_root_certificates()?;
    let implementation = match endpoint.scheme().to_lowercase().as_str()
    {
      "https" => Ok(Box::new(HttpCertificateClient::new(endpoint)) as Box<dyn CertificateClientImplementation>),
      "ldap" => Ok(Box::new(LdapCertificateClient::new(ldap)?) as Box<dyn CertificateClientImplementation>),
      scheme => Err(AdcsError::UnknownEndpointScheme(scheme.to_owned()))
    }?;
    Ok(Self
    {
      root_certificates,
      implementation
    })
  }

  pub fn root_certificates(&self) -> Vec<&'_ NamedCertificate>
  {
    self.root_certificates.iter().collect()
  }

  pub fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>
  {
    self.implementation.chain_certificates()
  }

  pub fn template_names(&self) -> Vec<&'_ str>
  {
    self.implementation.templates()
  }
}

trait CertificateClientImplementation
{
  fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>;
  fn templates(&self) -> Vec<&'_ str>;
}