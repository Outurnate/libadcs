use libdcerpc::{ms_icpr::{CertPassage, DWFlags, CertificateServerResponse}, Protocol};
use tracing::{event, Level, instrument};
use x509_certificate::X509Certificate;

use crate::{ldap::{LdapManager, LdapError}, client::{EnrollmentService, CertificateTemplate, Policy, EnrollmentResponse}};

pub fn get_policy(root_certificates: Vec<NamedCertificate>, ldap: &LdapManager) -> Result<Policy, LdapError>
{
  todo!()
}

pub struct LdapCertificateClient
{
  enrollment_services: Vec<EnrollmentService<String>>,
  templates: Vec<CertificateTemplate>
}

impl CertificateClientImplementation for LdapCertificateClient
{
  type Endpoint = String;
  type Response = CertificateServerResponse;
  type Error = LdapError;



  #[instrument(skip(self))]
  fn submit(&self, request: Vec<u8>, enrollment_service: &EnrollmentService<Self::Endpoint>) -> Result<Self::Response, Self::Error>
  {
    let endpoint = &enrollment_service.endpoint;
    let spn = format!("host/{}", endpoint);
    event!(Level::TRACE, "trying to connect to rpc endpoint {} with spn {}", endpoint, spn);
    let mut client = CertPassage::new(Protocol::Tcp, endpoint, &spn).unwrap();
    Ok(client.cert_server_request(DWFlags::REQUEST_TYPE_CMC | DWFlags::CMC_FULL_PKI_RESPONSE, &enrollment_service.certificate.nickname, None, "", request.as_slice()))
  }

  fn decode_response(response: Self::Response) -> Result<EnrollmentResponse, crate::DecodeError>
  {
    match response
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