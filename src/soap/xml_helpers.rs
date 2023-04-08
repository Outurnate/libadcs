use xmltree::Element;
use yaserde::{de, ser::{self, Serializer}};

use super::Error;

trait ElementExt
{
  fn deserialize<T: yaserde::YaDeserialize>(&self, error_mapper: impl FnOnce(String) -> Error) -> Result<T, Error>;
}

impl ElementExt for Element
{
  fn deserialize<T: yaserde::YaDeserialize>(&self, error_mapper: impl FnOnce(String) -> Error) -> Result<T, Error>
  {
    let mut buffer = Vec::new();
    self.write(&mut buffer)?;
    de::from_reader(buffer.as_slice()).map_err(error_mapper)
  }
}

fn to_string_with_config_and_start<T: yaserde::YaSerialize>(model: &T, config: &ser::Config, start_event_name: String) -> Result<String, String>
{
  let mut buf = Vec::new();
  let mut serializer = Serializer::new_from_writer(&mut buf, config);
  serializer.set_start_event_name(Some(start_event_name));
  yaserde::YaSerialize::serialize(model, &mut serializer)?;
  let data = std::str::from_utf8(buf.as_slice()).expect("Found invalid UTF-8");
  Ok(data.into())
}