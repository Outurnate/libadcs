use libdcerpc::{ms_icpr::{CertPassage, DWFlags, CertificateServerResponse}, Protocol};
use x509_certificate::{rfc2986::CertificationRequest, X509Certificate};
use log::{log, Level};

use crate::{ldap::{LdapManager}, AdcsError, cmc::CmcRequestBuilder, client::{EnrollmentService, CertificateTemplate, CertificateClientImplementation, Policy, EnrollmentResponse}};

pub struct LdapCertificateClient
{
  enrollment_services: Vec<EnrollmentService<String>>,
  templates: Vec<CertificateTemplate>
}

impl CertificateClientImplementation for LdapCertificateClient
{
  type Endpoint = String;

  fn get_policy(&self) -> &Policy<Self::Endpoint>
  {
    todo!()
  }

  fn submit(&self, request: CertificationRequest, template_name: &str) -> Result<EnrollmentResponse, AdcsError>
  {
    if let Some(template) = self.templates.iter().find(|x| x.cn == template_name)
    {
      if let Some(enrollment_service) = self.enrollment_services.iter().skip(1).find(|x| x.has_template(template_name))
      {
        let endpoint = &enrollment_service.endpoint;
        let spn = format!("host/{}", endpoint);
        log!(Level::Trace, "trying to connect to rpc endpoint {} with spn {}", endpoint, spn);
        let mut client = CertPassage::new(Protocol::Tcp, endpoint, &spn).unwrap();
        let request: Vec<u8> = CmcRequestBuilder::default()
          .add_certificate(request, template.get_attributes())
          .build()
          .try_into()?;
        match client.cert_server_request(DWFlags::REQUEST_TYPE_CMC | DWFlags::CMC_FULL_PKI_RESPONSE, &enrollment_service.certificate.nickname, None, "", request.as_slice())
        {
          CertificateServerResponse
          {
            disposition: Some(0x0000_0003), // issued
            certificate_chain,
            entity_certificate: Some(entity_certificate),
            disposition_message, ..
          } => Ok(EnrollmentResponse::Issued { entity: X509Certificate::from_der(entity_certificate)?, chain: vec![] }),
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