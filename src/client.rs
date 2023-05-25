use bcder::Oid;
use thiserror::Error;
use tracing::{event, Level, instrument};
use url::Url;
use x509_certificate::{rfc2986::CertificationRequest, X509Certificate};

use crate::{ClientAuthentication, NamedCertificate, cmc::{rfc5272::AttributeValue, CmcRequestBuilder}, EncodeError, DecodeError, AdcsError, ldap::LdapManager, ldap_client, http_client};

#[derive(Error, Debug)]
pub enum ClientError
{
  #[error("requested template {0} not found")]
  TemplateNotFound(String),

  #[error("no enrollment service found for template {0}")]
  NoEnrollmentServiceFound(String),

  #[error("encoding error: {0}")]
  EncodeFault(#[from] EncodeError),

  #[error("decoding error: {0}")]
  DecodeFault(#[from] DecodeError)
}

pub fn get_policy(uri: &Url, flags: &(), client_authentication: &ClientAuthentication, cost: &u64, ldap: &mut LdapManager) -> Result<Policy, AdcsError>
{
  match uri.scheme().to_lowercase().as_str()
  {
    "https" =>
    {
      if cfg!(feature = "policy_https")
      {
        Ok(Some(http_client::get_policy(uri)?))
      }
      else
      {
        event!(Level::WARN, "https scheme specified, though libadcs was compiled without https support.  ignoring");
        Ok(None)
      }
    },
    "ldap" =>
    {
      if cfg!(feature = "policy_ldap")
      {
        Ok(Some(ldap_client::get_policy(ldap)?))
      }
      else
      {
        event!(Level::WARN, "ldap scheme specified, though libadcs was compiled without ldap support.  ignoring");
        Ok(None)
      }
    },
    scheme =>
    {
      event!(Level::WARN, "unknown scheme specified: {}", scheme);
      Ok(None)
    }
  }
}

/*
  pub fn get_policy(&self) -> Result<Policy, AdcsError>
  {
    todo!()
  }

  pub fn get_name(&self) -> &'_ str
  {
    todo!()
  } */

pub trait EnrollmentClient
{
  fn submit(&self, policy: &Policy, request: Vec<u8>, template: &str) -> Result<EnrollmentResponse, AdcsError>;
}

pub enum EnrollmentResponse
{
  Issued
  {
    entity: X509Certificate,
    chain: Vec<X509Certificate>
  },
  Pending(u32),
  Rejected(String)
}

pub struct Policy
{
  enrollment_services: Vec<EnrollmentService>,
  templates: Vec<CertificateTemplate>
}

impl Policy
{
  pub fn get_id(&self) -> &'_ str
  {
    todo!()
  }

  pub fn get_enrollment_services_for_template(&self, template_name: &str) -> Result<impl Iterator<Item = EnrollmentService>, AdcsError>
  {
    if let Some(template) = self.templates.iter().find(|x| x.cn == template_name)
    {
      let mut enrollment_services = self.enrollment_services
        .iter()
        .filter(|enrollment_service| enrollment_service.has_template(template_name))
        .peekable();
      if enrollment_services.peek().is_none()
      {
        Err(AdcsError::Client(ClientError::NoEnrollmentServiceFound(template_name.to_owned())))
      }
      else
      {
        Ok(enrollment_services)
      }
    }
    else
    {
      Err(AdcsError::Client(ClientError::TemplateNotFound(template_name.to_owned())))
    }
  }
}

#[derive(Debug)]
pub struct EnrollmentService
{
  https_endpoints: Vec<(ClientAuthentication, bool, Url)>,
  rpc_endpoint: Option<String>,
  certificate: NamedCertificate,
  template_names: Vec<String>
}

impl EnrollmentService
{
  pub fn new(certificate: NamedCertificate, template_names: Vec<String>, https_endpoints: Vec<(ClientAuthentication, bool, Url)>, rpc_endpoint: Option<String>) -> Self
  {
    Self { https_endpoints, rpc_endpoint, certificate, template_names }
  }

  #[instrument]
  pub fn find_https_endpoints(&self, client_authentication: ClientAuthentication, renewing: bool) -> Vec<Url>
  {
    let client_authentication = client_authentication as u32;
    self.endpoints
      .iter()
      .filter(|endpoint|
        {
          if !renewing
          {
            !endpoint.renewal_only
          }
          else
          {
            true
          }
        })
      .filter(|endpoint| endpoint.client_authentication == client_authentication)
      .sorted_by(|a, b| Ord::cmp(&a.priority, &b.priority))
      .filter_map(|endpoint| match Url::parse(&endpoint.uri)
      {
        Ok(url) => Some(url),
        Err(err) =>
        {
          event!(Level::WARN, "ignoring endpoint due to invalid url.  endpoint is {:?}.  url error is {}", endpoint, err);
          None
        }
      })
  }

  pub fn find_rpc_endpoint(&self) -> &Option<String>
  {
    &self.rpc_endpoint
  }

  pub fn has_template(&self, template_name: &str) -> bool
  {
    self.template_names.iter().any(|x| template_name == x)
  }
}

pub struct CertificateTemplate
{
  pub cn: String,
  pub enroll: bool,
  pub auto_enroll: bool,
  pub extensions: Vec<(Oid, Vec<AttributeValue>)>
}

impl CertificateTemplate
{
  pub fn apply_to_request(&self, request: CertificationRequest) -> Result<Vec<u8>, EncodeError>
  {
    let request: Vec<u8> = CmcRequestBuilder::default()
      .add_certificate(request, self.extensions.clone())
      .build()
      .try_into()?;
    todo!()
  }
}