#![warn(clippy::unwrap_used)]
#![forbid(unsafe_code)]
#![allow(dead_code)]

mod ldap;
mod sddl;
mod ldap_client;
mod http_client;
mod cmc;

use std::{fmt::Display, convert::Infallible};
use bcder::decode::DecodeError;
use cryptographic_message_syntax::CmsError;
use http_client::HttpCertificateClient;
use ldap::LdapManager;
use ldap3::LdapError;
use ldap_client::LdapCertificateClient;
use thiserror::Error;
use url::Url;
use x509_certificate::{X509Certificate, rfc2986::CertificationRequest, X509CertificateError};

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
  UnknownEndpointScheme(String),
  #[error("requested template {0} not found")]
  TemplateNotFound(String),
  #[error("no enrollment service found for template {0}")]
  NoEnrollmentServiceFound(String),
  #[error("encoutered invalid x.509 certificate: {0}")]
  BadX509Certificate(#[from] X509CertificateError),
  #[error("cmc encoding error: {0}")]
  CmcEncodeError(#[from] CmsError),
  #[error("cmc decoding error: {0}")]
  CmcDecodeError(#[from] DecodeError<Infallible>),
  #[error("could not locate global catalog server")]
  NoGlobalCatalogServer,
  #[error("no rootdse (is this active directory???)")]
  NoRootDSE,
  #[error("could not locate ourselves in global catalog")]
  NoMyself
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
    let mut ldap = LdapManager::new(forest, tls)?;
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
  fn submit(&self, request: CertificationRequest, template: &str) -> Result<EnrollmentResponse>;
}

enum EnrollmentResponse
{
  Issued
  {
    entity: X509Certificate,
    chain: Vec<X509Certificate>
  },
  Pending(u32),
  Rejected(String)
}