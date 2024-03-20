use super::*;

const TEST_SIDS: &[&str] = &
[
  "S-1-5-32-544",
  "S-1-5-21-1004336348-1177238915-682003330-512",
  "S-1-0-0",
  "S-1-3-2",
  "S-1-5-80-0",
  "S-1-0x10000002A-0",
  "S-1-5",
  "S-1-5-113",
  "S-1-5-32-555"
];

#[test]
fn parsing_string()
{
  for sid in TEST_SIDS
  {
    SID::from_str(sid).unwrap();
  }
}

#[test]
fn round_trips()
{
  for sid in TEST_SIDS
  {
    assert_eq!(&SID::from_str(sid).unwrap().to_string(), sid);
  }
}