#![warn(clippy::unwrap_used)]
#![forbid(unsafe_code)]
#![allow(dead_code)]

mod ldap;
mod sddl;
mod ldap_client;
mod http_client;
mod cmc;
mod soap;
mod soap_operations;
mod client;

use client::{EnrollmentResponse, CertificateClientImplementation, CertificateClient, ClientError};
pub use reqwest::Url;

use std::fmt::Display;
use cryptographic_message_syntax::CmsError;
use http_client::HttpCertificateClient;
use ldap::LdapManager;
use ldap3::LdapError;
use ldap_client::LdapCertificateClient;
use thiserror::Error;
use x509_certificate::{X509Certificate, rfc2986::CertificationRequest, X509CertificateError};

#[derive(Debug, Clone, PartialEq, Eq)]
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
  #[error("could not locate global catalog server")]
  NoGlobalCatalogServer,
  #[error("no rootdse (is this active directory???)")]
  NoRootDSE,
  #[error("could not locate ourselves in global catalog")]
  NoMyself,

  #[error("client error: {0}")]
  Client(#[from] ClientError)
}

type Result<T> = std::result::Result<T, AdcsError>;

pub struct CertificateServicesClient
{
  root_certificates: Vec<NamedCertificate>,
  implementation: Box<dyn CertificateClient>
}

impl CertificateServicesClient
{
  pub fn new(forest: String, endpoint: Url, tls: bool) -> Result<Self>
  {
    let mut ldap = LdapManager::new(forest, tls)?;
    let root_certificates = ldap.get_root_certificates()?;
    Ok(Self
    {
      root_certificates,
      implementation: match endpoint.scheme().to_lowercase().as_str()
      {
        "https" => Ok(Box::new(HttpCertificateClient::new(endpoint)) as Box<dyn CertificateClient>),
        "ldap" => Ok(Box::new(LdapCertificateClient::new(ldap)?) as Box<dyn CertificateClient>),
        scheme => Err(AdcsError::UnknownEndpointScheme(scheme.to_owned()))
      }?
    })
  }

  pub fn root_certificates(&self) -> &Vec<NamedCertificate>
  {
    self.implementation.root_certificates()
  }

  pub fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>
  {
    self.implementation.chain_certificates()
  }

  pub fn template_names(&self) -> Vec<&'_ str>
  {
    self.implementation.templates()
  }

  pub fn submit(&self, request: CertificationRequest, template: &str) -> Result<EnrollmentResponse>
  {
    self.implementation.submit(request, template)
  }
}

#[derive(Error, Debug)]
pub enum DecodeError
{
  #[error("bad base64: {0}")]
  BadBase64(#[from] base64::DecodeError),

  #[error("bad certificate: {0}")]
  BadDer(#[from] x509_certificate::X509CertificateError),

  #[error("bad cms: {0}")]
  BadCms(#[from] cryptographic_message_syntax::CmsError)
}

#[derive(Error, Debug)]
pub enum EncodeError
{
  #[error("bad cms: {0}")]
  BadCms(#[from] cryptographic_message_syntax::CmsError)
}