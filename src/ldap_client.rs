use crate::{CertificateClientImplementation, ldap::{LdapManager, LdapEnrollmentService, LdapCertificateTemplate}, NamedCertificate};

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