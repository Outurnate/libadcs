#![warn(clippy::unwrap_used)]
#![forbid(unsafe_code)]

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

use itertools::Itertools;
pub use reqwest::Url;
pub use client::EnrollmentResponse;

use client::{ClientError, Policy, get_policy};
use soap::SoapHttpError;
use tracing::{event, Level};
use std::{fmt::Display, collections::HashMap, cmp::Ordering};
use ldap::{LdapManager, LdapError};
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
  #[error("client error: {0}")]
  Client(#[from] ClientError),

  #[error("ldap error: {0}")]
  Ldap(#[from] LdapError),

  #[error("soap error: {0}")]
  Soap(#[from] SoapHttpError),

  #[error("policy id not found: {0}")]
  PolicyIdNotFound(String)
}

pub type Result<T> = std::result::Result<T, AdcsError>;

// MS-XCEP 3.1.4.1.3.5
#[repr(u32)]
#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Clone, Copy)]
pub enum ClientAuthentication
{
  TransportKerberos = 2,
  Anonymous = 1,
  SoapUsernamePassword = 4,
  CmsSignature = 8
}

#[derive(Debug, Clone)]
pub struct PolicyEndpoint
{
  uri: Url,
  flags: (),
  client_authentication: ClientAuthentication,
  cost: u64
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
    self.flags == other.flags &&
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
      Ordering::Equal =>
      {
        match self.client_authentication.cmp(&other.client_authentication)
        {
          Ordering::Equal => self.flags.cmp(&other.flags),
          ord => ord
        }
      },
      ord => ord
    }
  }
}

pub struct CertificateServicesClient
{
  default_policy_id: String,
  policies: HashMap<String, Policy>,
  root_certificates: Vec<NamedCertificate>,
  chain_certificates: Vec<NamedCertificate>
}

impl CertificateServicesClient
{
  pub fn new(domain: String, default_policy_id: String, policy_endpoints: Vec<PolicyEndpoint>) -> Result<Self>
  {
    let mut ldap = LdapManager::new(domain, false)?;
    let root_certificates = ldap.get_root_certificates()?;
    let chain_certificates = ldap.get_ca_certificates()?
      .into_iter()
      .filter(|ca| !root_certificates.contains(ca))
      .collect();

    let policies = policy_endpoints
      .into_iter()
      .filter_map(|endpoint|
      {
        match get_policy(&endpoint.uri, &endpoint.flags, &endpoint.client_authentication, &endpoint.cost, &mut ldap)
        {
          Ok(policy) => Some((endpoint, policy.get_id(), policy)),
          Err(err) =>
          {
            event!(Level::WARN, "failed to get policy for endpoint {:?}: {}", endpoint, err);
            None
          }
        }
      })
      .group_by(|(_, key, _)| key)
      .into_iter()
      .filter_map(|(policy_id, policies)|
      {
        if let Some(policy) = policies.sorted_by(|(a, _, _), (b, _, _)| Ord::cmp(a, b)).map(|(_, _, policy)| policy).next()
        {
          Some(((*policy_id).to_owned(), policy))
        }
        else
        {
          event!(Level::WARN, "no working endpoints for policy, ignoring");
          None
          // ok this is literally unreachable....this whole statement must be crap
        }
      })
      .collect();

    Ok(Self
    {
      default_policy_id,
      policies,
      root_certificates,
      chain_certificates
    })
  }

  fn get_policy(&mut self, policy_id: impl Into<Option<String>>) -> Result<&'_ Policy>
  {
    let policy_id = policy_id.into().unwrap_or(self.default_policy_id.clone());
    if let Some(policy) = self.policies.get(&policy_id)
    {
      Ok(policy)
    }
    else
    {
      Err(AdcsError::PolicyIdNotFound(policy_id))
    }
  }

  pub fn root_certificates(&self) -> &Vec<NamedCertificate>
  {
    &self.root_certificates
  }

  pub fn chain_certificates(&self) -> &Vec<NamedCertificate>
  {
    &self.chain_certificates
  }

  pub fn template_names<'a>(&self, policy_id: impl Into<Option<String>>) -> Result<Vec<String>>
  {
    self.get_policy(policy_id)?.get_templates()
  }

  pub fn submit(&self, request: CertificationRequest, template: &str) -> Result<EnrollmentResponse>
  {
    todo!()
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