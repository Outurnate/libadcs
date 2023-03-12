use yaserde::ser::to_string;
use crate::schemas::Envelope;

mod schemas;

fn main()
{
  let mut model = Envelope::default();
  model.content.body.get_policies = Some(GetPoliciesType::default());
  println!("{}", to_string(&model).unwrap());
}