use crate::{ldap::{LdapManager, LdapError}, client::Policy, NamedCertificate};

pub fn get_policy(root_certificates: Vec<NamedCertificate>, ldap: &mut LdapManager) -> Result<Policy, LdapError>
{
  Ok(Policy::new_inner(ldap.get_id()?, ldap.get_enrollment_service()?, ldap.get_certificate_templates()?, root_certificates))
}

/*#[instrument]
fn submit(request: Vec<u8>, enrollment_service: &EnrollmentService) -> Result<(), ()>
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
}*/