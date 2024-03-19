use bcder::Oid;
use itertools::Itertools;
use thiserror::Error;
use tracing::{event, Level, instrument};
use url::Url;
use x509_certificate::{rfc2986::CertificationRequest, X509Certificate};

use crate::{ClientAuthentication, NamedCertificate, cmc::{rfc5272::AttributeValue, CmcRequestBuilder}, EncodeError, AdcsError, ldap::LdapManager, ldap_client, http_client, PolicyEndpoint};

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
  #[instrument]
  pub fn new(domain: String, policy_id: String, policy_endpoints: Vec<PolicyEndpoint>) -> Result<Self, AdcsError>
  {
    let mut ldap = LdapManager::new(domain, false)?;
    for policy_endpoint in policy_endpoints.into_iter().sorted()
    {
      match Policy::try_create(&policy_endpoint, &mut ldap)
      {
        Ok(policy) =>
        {
          if policy.get_id() == policy_id.as_str()
          {
            return Ok(policy)
          }
          else
          {
            event!(Level::INFO, "found policy from endpoint {} with id {}, which doesn't match requested id {}.  discarding", policy_endpoint, policy.get_id(), policy_id);
          }
        },
        Err(err) => event!(Level::WARN, "error while retrieving policy: {}.  skipping", err)
      }
    }
    Err(AdcsError::NoPolicies(policy_id))
  }

  fn try_create(endpoint: &PolicyEndpoint, ldap: &mut LdapManager) -> Result<Self, AdcsError>
  {
    let root_certificates = ldap.get_root_certificates()?;
    match endpoint.uri.scheme().to_lowercase().as_str()
    {
      "https" =>
      {
        if cfg!(feature = "policy_https")
        {
          Ok(http_client::get_policy(root_certificates, &endpoint.uri)?)
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

  pub(crate) fn new_inner(id: String, enrollment_services: Vec<EnrollmentService>, templates: Vec<CertificateTemplate>, root_certificates: Vec<NamedCertificate>) -> Self
  {
    let intermediate_certificates = enrollment_services
      .iter()
      .filter(|enrollment_service| !root_certificates.contains(enrollment_service.get_certificate()))
      .map(|enrollment_service| enrollment_service.get_certificate().to_owned())
      .collect();
    Policy { id, enrollment_services, templates, root_certificates, intermediate_certificates }
  }

  fn get_enrollment_services_for_template<'a>(&'a self, template: &'a CertificateTemplate) -> Result<impl Iterator<Item = &'_ EnrollmentService> + 'a, AdcsError>
  {
    if self.templates.iter().any(|x| x.cn == template.get_name() && x.can_enroll())
    {
      let enrollment_services = self.enrollment_services
        .iter()
        .filter(move |enrollment_service| enrollment_service.has_template(template.get_name()));
      Ok(enrollment_services)
    }
    else
    {
      Err(AdcsError::TemplateNotFound(template.get_name().to_string()))
    }
  }

  #[inline]
  pub fn get_id(&self) -> &'_ str
  {
    &self.id
  }

  #[inline]
  pub fn get_templates(&self) -> impl Iterator<Item = &'_ CertificateTemplate>
  {
    self.templates.iter()
  }

  #[inline]
  pub fn get_auto_enroll_templates(&self) -> impl Iterator<Item = &'_ CertificateTemplate>
  {
    self.templates.iter().filter(|x| x.should_auto_enroll())
  }

  #[inline]
  pub fn get_template_by_name(&self, name: impl AsRef<str>) -> Option<&'_ CertificateTemplate>
  {
    self.templates.iter().find(|template| template.get_name() == name.as_ref())
  }

  #[inline]
  pub fn get_root_certificates(&self) -> impl Iterator<Item = &'_ NamedCertificate>
  {
    self.root_certificates.iter()
  }

  #[inline]
  pub fn get_intermediate_certificates(&self) -> impl Iterator<Item = &'_ NamedCertificate>
  {
    self.intermediate_certificates.iter()
  }
}

#[derive(Debug, Clone)]
pub struct HttpsEndpoint
{
  client_authentication: ClientAuthentication,
  renewal_only: bool,
  uri: Url,
  priority: u32
}

impl HttpsEndpoint
{
  pub fn new(client_authentication: ClientAuthentication, renewal_only: bool, uri: Url, priority: u32) -> Self
  {
    Self
    {
      client_authentication,
      renewal_only,
      uri,
      priority
    }
  }
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
  cn: String,
  enroll: bool,
  auto_enroll: bool,
  extensions: Vec<(Oid, Vec<AttributeValue>)>
}

impl CertificateTemplate
{
  pub(crate) fn apply_to_request(&self, request: CertificationRequest) -> std::result::Result<Vec<u8>, EncodeError>
  {
    Ok(CmcRequestBuilder::default()
      .add_certificate(request, self.extensions.clone())
      .build()
      .try_into()?)
  }

  pub(crate) fn new(cn: String, enroll: bool, auto_enroll: bool, extensions: Vec<(Oid, Vec<AttributeValue>)>) -> Self
  {
    Self { cn, enroll, auto_enroll, extensions }
  }

  #[inline]
  fn can_enroll(&self) -> bool
  {
    self.enroll
  }

  #[inline]
  fn should_auto_enroll(&self) -> bool
  {
    self.enroll && self.auto_enroll
  }

  #[inline]
  pub fn get_name(&self) -> &'_ str
  {
    &self.cn
  }
}