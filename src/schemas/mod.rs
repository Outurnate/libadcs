mod soap;
mod wstrust;
mod wsse;
mod wstep;
mod xcep;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests
{
  use yaserde::{ser::to_string, de};
  use crate::{cmc::CmcMessage, schemas::{soap::{request_security_token, Envelope}, wstrust::RequestSecurityToken}};

  #[test]
  fn test_encode()
  {
    let envelope = request_security_token(CmcMessage(vec![0]), None);
    let xml = to_string(&envelope).expect("Error serializing");
    println!("{}", xml);

    let xml = include_str!("tests/wstep.xml");
    let envelope: Envelope<RequestSecurityToken> = de::from_str(xml).expect("Error deserializing");
    println!("{:?}", envelope);
  }
}