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

pub use reqwest::Url;
pub use client::EnrollmentResponse;

use client::{CertificateClient, ClientError};
use soap::SoapError;
use std::fmt::Display;
use http_client::HttpCertificateClient;
use ldap::{LdapManager, LdapError};
use ldap_client::LdapCertificateClient;
use thiserror::Error;
use x509_certificate::{X509Certificate, rfc2986::CertificationRequest};

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
  #[error("unknown endpoint scheme: {0}")]
  UnknownEndpointScheme(String),

  #[error("client error: {0}")]
  Client(#[from] ClientError),

  #[error("ldap error: {0}")]
  Ldap(#[from] LdapError),

  #[error("soap error: {0}")]
  Soap(#[from] SoapError)
}

type Result<T> = std::result::Result<T, AdcsError>;

pub struct CertificateServicesClient
{
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
      implementation: match endpoint.scheme().to_lowercase().as_str()
      {
        "https" => Ok(Box::new(HttpCertificateClient::new(endpoint, root_certificates)) as Box<dyn CertificateClient>),
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