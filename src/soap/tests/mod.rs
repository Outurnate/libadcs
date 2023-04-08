use yaserde_derive::{YaDeserialize, YaSerialize};
use super::{SoapBody, Error};


#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "none", namespace = "none: https://tempuri.org")]
struct Dummy;

#[test]
fn fault()
{
  let fault = include_str!("fault.xml");
  if let Err(Error::Fault(fault)) = Dummy::from_soap(fault.as_bytes())
  {
    assert_eq!(fault.to_string(), "fault env:Sender: Message does not have necessary info (node=None, role=Some(\"http://gizmos.com/order\"), detail=Some(Detail))".to_owned());
  }
  else
  {
    panic!();
  }
}