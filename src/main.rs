use schemas::{BodyType, RequestSecurityTokenType};
use yaserde::ser::to_string;
use crate::schemas::Envelope;

mod schemas;

fn main()
{
  let mut envelope = Envelope::default();
  envelope.content.body = BodyType::RequestSecurityToken(RequestSecurityTokenType::default());
  println!("{}", to_string(&envelope).unwrap());
}