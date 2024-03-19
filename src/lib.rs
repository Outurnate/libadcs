#![warn(clippy::unwrap_used)]
#![forbid(unsafe_code)]

extern crate num_derive;

mod ldap;
mod sddl;
mod cmc;
mod soap;
mod soap_operations;
mod client;

#[cfg(feature = "policy_ldap")]
mod ldap_client;
#[cfg(feature = "policy_https")]
mod http_client;

use num_derive::FromPrimitive;
use client::ConfigurationError;
use soap::SoapHttpError;
use std::{fmt::{Display, Formatter}, cmp::Ordering};
use ldap::LdapError;
use thiserror::Error;
use x509_certificate::X509Certificate;

pub use reqwest::Url;
pub use client::EnrollmentResponse;
pub use client::CertificateTemplate;
pub use client::Policy;

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
  #[error("ldap error: {0}")]
  Ldap(#[from] LdapError),

  #[error("soap error: {0}")]
  Soap(#[from] SoapHttpError),

  #[error("policy id not found: {0}")]
  PolicyIdNotFound(String),

  #[error("no policies for id {0}")]
  NoPolicies(String),

  #[error("no such template {0}")]
  TemplateNotFound(String),

  #[error("error in client configuration: {0}")]
  ConfigurationError(#[from] ConfigurationError)
}

pub type Result<T> = std::result::Result<T, AdcsError>;

// MS-XCEP 3.1.4.1.3.5
#[repr(u32)]
#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Clone, Copy, FromPrimitive, Default)]
pub enum ClientAuthentication
{
  TransportKerberos = 2,
  #[default]
  Anonymous = 1,
  SoapUsernamePassword = 4,
  CmsSignature = 8
}

#[derive(Debug, Clone)]
pub struct PolicyEndpoint
{
  uri: Url,
  client_authentication: ClientAuthentication,
  cost: u64
}

impl Display for PolicyEndpoint
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result
  {
    f.write_str(self.uri.as_str())
  }
}

// cost, ASCENDING
// then clientauth == kerberos
// then clientauth == anon
// then whatever the hell you want
// MS CAESO 4.4.5.3.2.3
impl PartialOrd for PolicyEndpoint
{
  fn partial_cmp(&self, other: &Self) -> Option<Ordering>
  {
    Some(self.cmp(other))
  }
}

impl PartialEq for PolicyEndpoint
{
  fn eq(&self, other: &Self) -> bool
  {
    self.client_authentication == other.client_authentication &&
    self.cost == other.cost
  }
}

impl Eq for PolicyEndpoint {}

impl Ord for PolicyEndpoint
{
  fn cmp(&self, other: &Self) -> Ordering
  {
    match self.cost.cmp(&other.cost)
    {
      Ordering::Equal => self.client_authentication.cmp(&other.client_authentication),
      ord => ord
    }
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