use uuid::Uuid;
use crate::cmc::CmcRequest;
use crate::soap::SoapBody;
use crate::soap::HeaderBuilder;
use crate::soap::EndpointReferenceBuilder;
use crate::soap_operations::wstrust::RequestSecurityToken;

#[test]
/*fn round_trip()
{
  let header = HeaderBuilder::default()
    .reply_to(EndpointReferenceBuilder::default()
      .address("http://www.w3.org/2005/08/addressing/anonymous".to_owned())
      .build().expect("error building endpoint reference"))
    .action("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep".to_owned())
    .message_id(format!("urn:uuid:{}", Uuid::new_v4()))
    .build().expect("error building header");
  let body = RequestSecurityToken::new(CmcRequest(vec![0]), Some("7777".to_owned())).expect("failed to create cmc message");
  let envelope = body.clone_to_soap(&header).expect("failed to create soap envelope");

  let (new_header, new_body) = RequestSecurityToken::from_soap(envelope.as_bytes()).expect("failed to reparse soap envelope");

  assert_eq!(header, new_header.expect("header lost in round trip"));
  assert_eq!(body, new_body);
}*/

#[test]
fn parse_known()
{
  let known = include_str!("wstep.xml");
  RequestSecurityToken::from_soap(known.as_bytes()).expect("failed to parse known good soap message");
}