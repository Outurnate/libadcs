use bcder::Oid;
use itertools::Itertools;
use thiserror::Error;
use url::Url;
use x509_certificate::{rfc2986::CertificationRequest, X509Certificate};

use crate::{ClientAuthentication, NamedCertificate, cmc::{rfc5272::AttributeValue, CmcRequestBuilder}, EncodeError, AdcsError, ldap::LdapManager, ldap_client, http_client};

#[derive(Error, Debug)]
pub enum ConfigurationError
{
  #[error("https scheme specified, though libadcs was compiled without https support")]
  NoHttpsSupport,

  #[error("ldap scheme specified, though libadcs was compiled without https support")]
  NoLdapSupport,

  #[error("unknown scheme specified: {0}")]
  UnknownScheme(String)
}

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

#[derive(Debug, Clone)]
pub struct Policy
{
  id: String,
  enrollment_services: Vec<EnrollmentService>,
  templates: Vec<CertificateTemplate>,
  root_certificates: Vec<NamedCertificate>,
  intermediate_certificates: Vec<NamedCertificate>
}

impl Policy
{
  pub fn new(uri: &Url, flags: &(), client_authentication: &ClientAuthentication, cost: &u64, ldap: &mut LdapManager) -> Result<Policy, AdcsError>
  {
    let root_certificates = ldap.get_root_certificates()?;
    match uri.scheme().to_lowercase().as_str()
    {
      "https" =>
      {
        if cfg!(feature = "policy_https")
        {
          Ok(http_client::get_policy(root_certificates, uri)?)
        }
        else
        {
          Err(ConfigurationError::NoHttpsSupport.into())
        }
      },
      "ldap" =>
      {
        if cfg!(feature = "policy_ldap")
        {
          Ok(ldap_client::get_policy(root_certificates, ldap)?)
        }
        else
        {
          Err(ConfigurationError::NoLdapSupport.into())
        }
      },
      scheme =>
      {
        Err(ConfigurationError::UnknownScheme(scheme.to_owned()).into())
      }
    }
  }

  pub fn get_id(&self) -> &'_ str
  {
    &self.id
  }

  pub fn get_enrollment_services_for_template(&self, template_name: String) -> Result<impl Iterator<Item = &'_ EnrollmentService>, AdcsError>
  {
    if self.templates.iter().find(|x| x.cn == template_name).is_some()
    {
      let enrollment_services = self.enrollment_services
        .iter()
        .filter(move |enrollment_service| enrollment_service.has_template(&template_name));
      Ok(enrollment_services)
    }
    else
    {
      Err(AdcsError::TemplateNotFound(template_name))
    }
  }

  pub fn get_templates(&self) -> impl Iterator<Item = &'_ str>
  {
    self.templates.iter().map(|template| template.cn.as_str())
  }
}

#[derive(Debug, Clone)]
pub struct HttpsEndpoint
{
  client_authentication: ClientAuthentication,
  renewal_only: bool,
  uri: Url,
  priority: u64
}

#[derive(Debug, Clone)]
pub struct EnrollmentService
{
  https_endpoints: Vec<HttpsEndpoint>,
  rpc_endpoint: Option<String>,
  certificate: NamedCertificate,
  template_names: Vec<String>
}

impl EnrollmentService
{
  pub fn new(certificate: NamedCertificate, template_names: Vec<String>, https_endpoints: Vec<HttpsEndpoint>, rpc_endpoint: Option<String>) -> Self
  {
    Self { https_endpoints, rpc_endpoint, certificate, template_names }
  }

  pub fn find_https_endpoints(&self, client_authentication: ClientAuthentication, renewing: bool) -> impl Iterator<Item = &'_ Url>
  {
    self.https_endpoints
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
      .map(|endpoint| &endpoint.uri)
  }

  pub fn find_rpc_endpoint(&self) -> &Option<String>
  {
    &self.rpc_endpoint
  }

  pub fn has_template(&self, template_name: &str) -> bool
  {
    self.template_names.iter().any(|x| template_name == x)
  }

  pub fn get_certificate(&self) -> &'_ NamedCertificate
  {
    &self.certificate
  }
}

#[derive(Debug, Clone)]
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