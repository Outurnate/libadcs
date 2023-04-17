use bcder::Oid;
use thiserror::Error;
use x509_certificate::{rfc2986::CertificationRequest, X509Certificate};

use crate::{NamedCertificate, cmc::{rfc5272::AttributeValue, CmcRequestBuilder}, EncodeError, DecodeError, AdcsError};

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

pub trait CertificateClient
{
  fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>;
  fn templates(&self) -> Vec<&'_ str>;
  fn root_certificates(&self) -> &Vec<NamedCertificate>;
  fn submit(&self, request: CertificationRequest, template: &str) -> Result<EnrollmentResponse, AdcsError>;
}

pub trait CertificateClientImplementation
{
  type Endpoint;
  type Error;
  type Response;

  fn get_policy(&self) -> &Policy<Self::Endpoint>;
  fn submit(&self, request: Vec<u8>, enrollment_service: &EnrollmentService<Self::Endpoint>) -> Result<Self::Response, Self::Error>;
  fn decode_response(response: Self::Response) -> Result<EnrollmentResponse, DecodeError>;
}

impl<T: CertificateClientImplementation> CertificateClient for T where AdcsError: From<<T as CertificateClientImplementation>::Error>
{
  fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>
  {
    self.get_policy().enrollment_services
      .iter()
      .map(|service| &service.certificate)
      .collect()
  }

  fn templates(&self) -> Vec<&'_ str>
  {
    self.get_policy().templates.iter().map(|template| template.cn.as_str()).collect()
  }

  fn root_certificates(&self) -> &Vec<NamedCertificate>
  {
    &self.get_policy().root_certificates
  }

  fn submit(&self, request: CertificationRequest, template_name: &str) -> Result<EnrollmentResponse, AdcsError>
  {
    if let Some(template) = self.get_policy().templates.iter().find(|x| x.cn == template_name)
    {
      if let Some(enrollment_service) = self.get_policy().enrollment_services.iter().find(|x| x.has_template(template_name))
      {
        let request = template.apply_to_request(request).map_err(ClientError::EncodeFault)?;
        let response = self.submit(request, enrollment_service)?;
        Ok(T::decode_response(response).map_err(ClientError::DecodeFault)?)
      }
      else
      {
        Err(AdcsError::Client(ClientError::NoEnrollmentServiceFound(template_name.to_owned())))
      }
    }
    else
    {
      Err(AdcsError::Client(ClientError::TemplateNotFound(template_name.to_owned())))
    }
  }
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

pub struct Policy<E>
{
  pub enrollment_services: Vec<EnrollmentService<E>>,
  pub templates: Vec<CertificateTemplate>,
  pub root_certificates: Vec<NamedCertificate>
}

#[derive(Debug)]
pub struct EnrollmentService<E>
{
  pub endpoint: E,
  pub certificate: NamedCertificate,
  pub template_names: Vec<String>
}

impl<E> EnrollmentService<E>
{
  pub fn has_template(&self, template_name: &str) -> bool
  {
    self.template_names.iter().any(|x| template_name == x)
  }
}

pub struct CertificateTemplate
{
  pub cn: String,
  pub enroll: bool,
  pub auto_enroll: bool
}

impl CertificateTemplate
{
  pub fn apply_to_request(&self, request: CertificationRequest) -> Result<Vec<u8>, EncodeError>
  {
    let request: Vec<u8> = CmcRequestBuilder::default()
      .add_certificate(request, self.get_attributes())
      .build()
      .try_into()?;
    todo!()
  }

  pub fn get_attributes(&self) -> impl Iterator<Item = (Oid, Vec<AttributeValue>)>
  {
    vec![].into_iter() // TODO
  }
}