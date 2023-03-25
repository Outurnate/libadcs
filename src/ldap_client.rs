use libdcerpc::{ms_icpr::{CertPassage, DWFlags, CertificateServerResponse}, Protocol};
use x509_certificate::{rfc2986::CertificationRequest, X509Certificate};

use crate::{CertificateClientImplementation, ldap::{LdapManager, LdapEnrollmentService, LdapCertificateTemplate}, NamedCertificate, AdcsError, EnrollmentResponse, cmc::{wrap_in_cms, unwrap_from_cms}};

pub struct LdapCertificateClient
{
  enrollment_services: Vec<LdapEnrollmentService>,
  templates: Vec<LdapCertificateTemplate>
}

impl CertificateClientImplementation for LdapCertificateClient
{
  fn chain_certificates(&self) -> Vec<&'_ NamedCertificate>
  {
    self.enrollment_services.iter().map(|service| service.get_certificate()).collect()
  }

  fn templates(&self) -> Vec<&'_ str>
  {
    self.templates.iter().map(|template| template.get_name()).collect()
  }

  fn submit(&self, request: CertificationRequest, template_name: &str) -> Result<EnrollmentResponse, AdcsError>
  {
    if let Some(template) = self.templates.iter().find(|x| x.get_name() == template_name)
    {
      if let Some(enrollment_service) = self.enrollment_services.iter().find(|x| x.has_template(template_name))
      {
        let mut client = CertPassage::new(Protocol::Tcp, enrollment_service.get_endpoint(), &format!("host/{}", enrollment_service.get_endpoint())).unwrap();
        match client.cert_server_request(DWFlags::REQUEST_TYPE_CMC | DWFlags::CMC_FULL_PKI_RESPONSE, &enrollment_service.get_certificate().nickname, None, "", &wrap_in_cms(request, template.get_attributes())?)
        {
          CertificateServerResponse
          {
            disposition: Some(0x0000_0003), // issued
            certificate_chain,
            entity_certificate: Some(entity_certificate),
            disposition_message, ..
          } => Ok(EnrollmentResponse::Issued { entity: X509Certificate::from_der(entity_certificate)?, chain: certificate_chain.map(|x| unwrap_from_cms(x)).unwrap()? }),
          CertificateServerResponse
          {
            disposition: Some(0x0000_0005), // taken under submission
            request_id: Some(request_id), ..
          } => Ok(EnrollmentResponse::Pending(request_id)),
          CertificateServerResponse
          {
            disposition: Some(disposition), // error
            disposition_message, ..
          } => Ok(EnrollmentResponse::Rejected(format!("rejected ({}): {}", disposition, disposition_message.unwrap_or_default()))),
          _ => todo!()
        }
      }
      else
      {
        Err(AdcsError::NoEnrollmentServiceFound(template_name.to_owned()))
      }
    }
    else
    {
      Err(AdcsError::TemplateNotFound(template_name.to_owned()))
    }
  }
}

impl LdapCertificateClient
{
  pub fn new(mut ldap: LdapManager) -> crate::Result<Self>
  {
    Ok(Self
    {
      enrollment_services: ldap.get_enrollment_service()?,
      templates: ldap.get_certificate_templates()?
    })
  }
}