use uuid::Uuid;
use xml::{reader, namespace::Namespace, writer, attribute::OwnedAttribute};
use yaserde::{de::{Deserializer, self}, __derive_debug, Visitor, __derive_trace, ser::Serializer};
use yaserde_derive::{YaDeserialize, YaSerialize};
use std::{io::{Read, Write}, borrow::Cow, marker::PhantomData};

use crate::cmc::CmcMessage;

use super::{wstrust::{RequestSecurityToken}};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Envelope<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default>
{
  header: HeaderType,
  body: BodyType<T>
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> yaserde::YaSerialize for Envelope<T>
{
  fn serialize<W: Write>(&self, writer: &mut Serializer<W>) -> Result<(), String>
  {
    let skip = writer.skip_start_end();
    if !skip
    {
      let child_attributes = vec![];
      let child_attributes_namespace = Namespace::empty();
      let yaserde_label = writer
        .get_start_event_name()
        .unwrap_or_else(|| "soap:Envelope".to_string());
      let struct_start_event = writer::XmlEvent::start_element(yaserde_label.as_ref())
        .ns("soap", "http://www.w3.org/2003/05/soap-envelope");
      let event: ::yaserde::__xml::writer::events::XmlEvent = struct_start_event.into();
      if let writer::events::XmlEvent::StartElement { name, attributes, namespace } = event
      {
        let mut attributes: Vec<OwnedAttribute> = attributes
          .into_owned()
          .to_vec()
          .iter()
          .map(|k| k.to_owned())
          .collect();
        attributes.extend(child_attributes);
        let all_attributes = attributes.iter().map(|ca| ca.borrow()).collect();
        let mut all_namespaces = namespace.into_owned();
        all_namespaces.extend(&child_attributes_namespace);
        writer.write(writer::events::XmlEvent::StartElement { name, attributes: Cow::Owned(all_attributes), namespace: Cow::Owned(all_namespaces) })
          .map_err(|e| e.to_string())?;
      }
      else
      {
        unreachable!()
      }
    }
    writer.set_start_event_name(Some("soap:Header".to_string()));
    writer.set_skip_start_end(false);
    self.header.serialize(writer)?;
    writer.set_start_event_name(Some("soap:Body".to_string()));
    writer.set_skip_start_end(false);
    self.body.serialize(writer)?;
    if !skip
    {
      let struct_end_event = writer::XmlEvent::end_element();
      writer.write(struct_end_event).map_err(|e| e.to_string())?;
    }
    Ok(())
  }

  fn serialize_attributes(&self, mut source_attributes: Vec<OwnedAttribute>, mut source_namespace: Namespace) -> Result<(Vec<OwnedAttribute>, Namespace), String>
  {
    let child_attributes = Vec::<OwnedAttribute>::new();
    let child_attributes_namespace = Namespace::empty();
    let struct_start_event = writer::XmlEvent::start_element("temporary_element_to_generate_attributes")
      .ns("soap", "http://www.w3.org/2003/05/soap-envelope");
    let event: writer::events::XmlEvent = struct_start_event.into();
    if let writer::events::XmlEvent::StartElement { attributes, namespace, .. } = event
    {
      source_namespace.extend(&namespace.into_owned());
      source_namespace.extend(&child_attributes_namespace);
      let a: Vec<OwnedAttribute> = attributes
        .into_owned()
        .to_vec()
        .iter()
        .map(|k| k.to_owned())
        .collect();
      source_attributes.extend(a);
      source_attributes.extend(child_attributes);
      Ok((source_attributes, source_namespace))
    }
    else
    {
      unreachable!();
    }
  }
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + yaserde::YaDeserialize + Default> yaserde::YaDeserialize for Envelope<T>
{
  fn deserialize<R: Read>(reader: &mut Deserializer<R>) -> ::std::result::Result<Self, ::std::string::String>
  {
    let (named_element, struct_namespace) =
      if let reader::XmlEvent::StartElement { name, .. } = reader.peek()?.to_owned()
      {
        (name.local_name.to_owned(), name.namespace)
      }
      else
      {
        (String::from("soap:EnvelopeType"), None)
      };
    let start_depth = reader.depth();
    __derive_debug!("Struct {} @ {}: start to parse {:?}", stringify!(EnvelopeType), start_depth, named_element);
    if reader.depth() == 0
    {
      if let Some(namespace) = struct_namespace
      {
        match namespace.as_str()
        {
          "http://www.w3.org/2003/05/soap-envelope" => {}
          bad_namespace => return Err(format!("bad namespace for {}, found {}", named_element, bad_namespace))
        }
      }
    }

    let mut __header_value: HeaderType = HeaderType::default();
    let mut __body_value = BodyType::<T>::default();

    struct VisitorHeaderType;
    impl<'de> Visitor<'de> for VisitorHeaderType
    {
      type Value = HeaderType;
      fn visit_str(self, v: &str) -> Result<Self::Value, String>
      {
        let content = "<".to_string() + "HeaderType>" + v + "</HeaderType>";
        de::from_str(&content)
      }
    }

    struct VisitorBodyType<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default>(PhantomData<T>);
    impl<'de, T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> Visitor<'de> for VisitorBodyType<T>
    {
      type Value = BodyType<T>;
      fn visit_str(self, v: &str) -> Result<Self::Value, String>
      {
        let content = "<".to_string() + "BodyType>" + v + "</BodyType>";
        de::from_str(&content)
      }
    }

    let mut depth = 0;
    loop
    {
      let event = reader.peek()?.to_owned();
      __derive_trace!("Struct {} @ {}: matching {:?}", stringify!(EnvelopeType), start_depth, event);
      match event
      {
        reader::XmlEvent::StartElement { ref name, .. }=>
        {
          if depth == 0 && name.local_name == "soap:EnvelopeType"
          {
            reader.next_event()?;
          }
          else
          {
            match name.local_name.as_str()
            {
              "Header" =>
              {
                if depth == 0
                {
                  let _root = reader.next_event();
                }
                if let Ok(reader::XmlEvent::StartElement { .. }) = reader.peek()
                {
                  let value = HeaderType::deserialize(reader)?;
                  __header_value = value;
                  let _event = reader.next_event()?;
                }
              }
              "Body" =>
              {
                if depth == 0
                {
                  let _root = reader.next_event();
                }
                if let Ok(reader::XmlEvent::StartElement { .. }) = reader.peek()
                {
                  let value = BodyType::deserialize(reader)?;
                  __body_value = value;
                  let _event = reader.next_event()?;
                }
              }
              _ =>
              {
                let _event = reader.next_event()?;
                if depth > 0
                {
                  reader.skip_element(|_| {})?;
                }
              }
            }
          }
          if depth == 0 {}
          depth += 1;
        }
        reader::XmlEvent::EndElement { ref name } =>
        {
          if name.local_name == named_element && reader.depth() == start_depth + 1
          {
            break;
          }
          reader.next_event()?;
          depth -= 1;
        }
        reader::XmlEvent::EndDocument => {}
        reader::XmlEvent::Characters(_) =>
        {
          reader.next_event()?;
        }
        event =>
        {
          return Err(format!("unknown event {:?}", event));
        }
      }
    }
    __derive_debug!("Struct {} @ {}: success", stringify!(EnvelopeType), start_depth);
    Ok(Envelope
    {
      header: __header_value,
      body: __body_value,
    })
  }
}

#[derive(Clone, Debug, PartialEq)]
enum BodyType<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default>
{
  Fault(FaultType),
  NotUnderstood(NotUnderstoodType),
  Upgrade(UpgradeType),
  Body(T)
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> Default for BodyType<T>
{
  fn default() -> Self
  {
    Self::Body(T::default())
  }
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> yaserde::YaSerialize for BodyType<T>
{
  fn serialize<W: Write>(&self, writer: &mut Serializer<W>) -> Result<(), String>
  {
    let skip = writer.skip_start_end();
    if !skip
    {
      let child_attributes = ::std::vec![];
      let child_attributes_namespace = Namespace::empty();
      let yaserde_label = writer
          .get_start_event_name()
          .unwrap_or_else(|| "soap:BodyType".to_string());
      let struct_start_event = writer::XmlEvent::start_element(yaserde_label.as_ref())
        .ns("soap", "http://www.w3.org/2003/05/soap-envelope");
      let event: writer::events::XmlEvent = struct_start_event.into();
      if let writer::events::XmlEvent::StartElement { name, attributes, namespace } = event
      {
        let mut attributes: Vec<OwnedAttribute> = attributes
          .into_owned()
          .to_vec()
          .iter()
          .map(|k| k.to_owned())
          .collect();
        attributes.extend(child_attributes);
        let all_attributes = attributes.iter().map(|ca| ca.borrow()).collect();
        let mut all_namespaces = namespace.into_owned();
        all_namespaces.extend(&child_attributes_namespace);
        writer
          .write(writer::events::XmlEvent::StartElement { name, attributes: Cow::Owned(all_attributes), namespace: Cow::Owned(all_namespaces) })
          .map_err(|e| e.to_string())?;
      }
      else
      {
        unreachable!()
      }
    }

    match self
    {
      BodyType::Fault { .. } =>
      {
        let struct_start_event = writer::XmlEvent::start_element("soap:Fault");
        writer.write(struct_start_event).map_err(|e| e.to_string())?;
        if let BodyType::Fault(ref item) = self
        {
          writer.set_start_event_name(::std::option::Option::None);
          writer.set_skip_start_end(true);
          item.serialize(writer)?;
        }
        let struct_end_event = writer::XmlEvent::end_element();
        writer.write(struct_end_event).map_err(|e| e.to_string())?;
      }
      BodyType::NotUnderstood { .. } =>
      {
        let struct_start_event = writer::XmlEvent::start_element("soap:NotUnderstood");
        writer.write(struct_start_event).map_err(|e| e.to_string())?;
        if let BodyType::NotUnderstood(ref item) = self
        {
          writer.set_start_event_name(::std::option::Option::None);
          writer.set_skip_start_end(true);
          item.serialize(writer)?;
        }
        let struct_end_event = writer::XmlEvent::end_element();
        writer.write(struct_end_event).map_err(|e| e.to_string())?;
      }
      BodyType::Upgrade { .. } =>
      {
        let struct_start_event = writer::XmlEvent::start_element("soap:Upgrade");
        writer.write(struct_start_event).map_err(|e| e.to_string())?;
        if let BodyType::Upgrade(ref item) = self
        {
          writer.set_start_event_name(::std::option::Option::None);
          writer.set_skip_start_end(true);
          item.serialize(writer)?;
        }
        let struct_end_event = writer::XmlEvent::end_element();
        writer.write(struct_end_event).map_err(|e| e.to_string())?;
      }
      BodyType::Body(ref item) =>
      {
        writer.set_start_event_name(::std::option::Option::None);
        writer.set_skip_start_end(true);
        item.serialize(writer)?;
      }
    }
    if !skip
    {
      let struct_end_event = writer::XmlEvent::end_element();
      writer.write(struct_end_event).map_err(|e| e.to_string())?;
    }
    Ok(())
  }

  fn serialize_attributes(&self, mut source_attributes: Vec<OwnedAttribute>, mut source_namespace: Namespace) -> Result<(Vec<OwnedAttribute>, Namespace), String>
  {
    let child_attributes = Vec::<OwnedAttribute>::new();
    let child_attributes_namespace = Namespace::empty();
    let struct_start_event = writer::XmlEvent::start_element("temporary_element_to_generate_attributes")
      .ns("soap", "http://www.w3.org/2003/05/soap-envelope");
    let event: writer::events::XmlEvent = struct_start_event.into();
    if let writer::events::XmlEvent::StartElement { attributes, namespace, .. } = event
    {
      source_namespace.extend(&namespace.into_owned());
      source_namespace.extend(&child_attributes_namespace);
      let a: Vec<OwnedAttribute> = attributes
          .into_owned()
          .to_vec()
          .iter()
          .map(|k| k.to_owned())
          .collect();
      source_attributes.extend(a);
      source_attributes.extend(child_attributes);
      Ok((source_attributes, source_namespace))
    }
    else
    {
      unreachable!();
    }
  }
}

impl<T: yaserde::YaSerialize + yaserde::YaDeserialize + Default> yaserde::YaDeserialize for BodyType<T>
{
  fn deserialize<R: Read>(reader: &mut Deserializer<R>) -> Result<Self, String>
  {
    let (named_element,enum_namespace) =
      if let reader::XmlEvent::StartElement { name, .. } = reader.peek()?.to_owned()
      {
        (name.local_name.to_owned(), name.namespace)
      }
      else
      {
        (String::from("soap:BodyType"), None)
      };
    let start_depth = reader.depth();
    __derive_debug!("Enum {} @ {}: start to parse {:?}", stringify!(BodyType), start_depth, named_element);
    if let Some(namespace) = enum_namespace
    {
      match namespace.as_str()
      {
        "http://www.w3.org/2003/05/soap-envelope" => {}
        bad_namespace => return Err(format!("bad namespace for {}, found {}", named_element, bad_namespace))
      }
    }
    let mut enum_value = None;
    loop
    {
      let event = reader.peek()?.to_owned();
      __derive_trace!("Enum {} @ {}: matching {:?}", stringify!(BodyType), start_depth, event);
      match event
      {
        reader::XmlEvent::StartElement { ref name, .. } =>
        {
          struct VisitorFault;
          impl<'de> Visitor<'de> for VisitorFault
          {
            type Value = FaultType;
            fn visit_str(self, v: &str) -> Result<Self::Value, String>
            {
              de::from_str(&format!("<FaultType>{}</FaultType>", v))
            }
          }

          struct VisitorNotUnderstood;
          impl<'de> Visitor<'de> for VisitorNotUnderstood
          {
            type Value = NotUnderstoodType;
            fn visit_str(self, v: &str) -> Result<Self::Value, String>
            {
              de::from_str(&format!("<NotUnderstoodType>{}</NotUnderstoodType>", v))
            }
          }

          struct VisitorUpgrade;
          impl<'de> Visitor<'de> for VisitorUpgrade
          {
            type Value = UpgradeType;
            fn visit_str(self,v: &str,) -> Result<Self::Value, String>
            {
              de::from_str(&format!("<UpgradeType>{}</UpgradeType>", v))
            }
          }

          match name.local_name.as_str()
          {
            "Fault" =>
            {
              match FaultType::deserialize(reader)
              {
                Ok(value) =>
                {
                  enum_value = Some(BodyType::Fault(value));
                  let _root = reader.next_event();
                },
                Err(msg) => return Err(msg)
              }
            }
            "NotUnderstood" =>
            {
              match NotUnderstoodType::deserialize(reader)
              {
                Ok(value) =>
                {
                  enum_value = Option::Some(BodyType::NotUnderstood(value));
                  let _root = reader.next_event();
                },
                Err(msg) => return Err(msg)
              }
            }
            "Upgrade" =>
            {
              match UpgradeType::deserialize(reader)
              {
                Ok(value) =>
                {
                  enum_value = Some(BodyType::Upgrade(value));
                  let _root = reader.next_event();
                },
                Err(msg) => return Err(msg)
              }
            }
            _named_element =>
            {
              let _root = reader.next_event();
            }
          }
          if let reader::XmlEvent::Characters(content) = reader.peek()?.to_owned()
          {
            match content.as_str()
            {
              "Fault" =>
              {
                match FaultType::deserialize(reader)
                {
                  Ok(value) =>
                  {
                    enum_value = Some(BodyType::Fault(value));
                    let _root = reader.next_event();
                  },
                  Err(msg) => return Err(msg)
                }
              }
              "NotUnderstood" =>
              {
                match NotUnderstoodType::deserialize(reader)
                {
                  Ok(value) =>
                  {
                    enum_value = Some(BodyType::NotUnderstood(value));
                    let _root = reader.next_event();
                  },
                  Err(msg) => return Err(msg)
                }
              }
              "Upgrade" =>
              {
                match UpgradeType::deserialize(reader)
                {
                  Ok(value) =>
                  {
                    enum_value = Some(BodyType::Upgrade(value));
                    let _root = reader.next_event();
                  },
                  Err(msg) => return Err(msg),
                }
              }
              _ => {}
            }
          }
        }
        reader::XmlEvent::EndElement { ref name } =>
        {
          if name.local_name == named_element && reader.depth() == start_depth + 1
          {
            break;
          }
          let _root = reader.next_event();
        }
        reader::XmlEvent::Characters(_) =>
        {
          let _root = reader.next_event();
        }
        reader::XmlEvent::EndDocument =>
        {
          return Err("End of document, missing some content ?".to_owned());
        }
        event =>
        {
          return Err(format!("unknown event {:?}", event))
        }
      }
    }
    __derive_debug!("Enum {} @ {}: success", stringify!(BodyType), start_depth);
    match enum_value
    {
      Some(value) => Ok(value), 
      None => Ok(BodyType::default())
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultType
{
  #[yaserde(rename = "Code", prefix = "soap")]
  code: FaultCode,

  #[yaserde(rename = "Reason", prefix = "soap")]
  reason: FaultReason,
  
  #[yaserde(rename = "Node", prefix = "soap")]
  node: Option<String>,
  
  #[yaserde(rename = "Role", prefix = "soap")]
  role: Option<String>,

  #[yaserde(rename = "Detail", prefix = "soap")]
  detail: Option<Detail>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultReason
{
  #[yaserde(rename = "Text", prefix = "soap")]
  texts: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct FaultCode
{
  #[yaserde(rename = "Value", prefix = "soap")]
  value: String,
  
  #[yaserde(rename = "Subcode", prefix = "soap")]
  subcode: Option<SubCode>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct SubCode
{
  #[yaserde(rename = "Value", prefix = "soap")]
  value: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct Detail
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct NotUnderstoodType
{
  #[yaserde(attribute)]
  qname: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct SupportedEnvType
{
  #[yaserde(attribute)]
  qname: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
struct UpgradeType
{
  #[yaserde(rename = "SupportedEnvelope", prefix = "soap")]
  supported_envelopes: Vec<SupportedEnvType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct HeaderType
{
  #[yaserde(rename = "ReplyTo", prefix = "wsa")]
  reply_to: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "From", prefix = "wsa")]
  from: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "FaultTo", prefix = "wsa")]
  fault_to: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "EndpointReference", prefix = "wsa")]
  endpoint_reference: Option<EndpointReferenceType>,
  
  #[yaserde(rename = "To", prefix = "wsa")]
  to: Option<String>,
  
  #[yaserde(rename = "Action", prefix = "wsa")]
  action: Option<String>,
  
  #[yaserde(rename = "ProblemIRI", prefix = "wsa")]
  problem_iri: Option<String>,
  
  #[yaserde(rename = "MessageID", prefix = "wsa")]
  message_id: Option<String>,
  
  #[yaserde(rename = "RetryAfter", prefix = "wsa")]
  retry_after: Option<u64>,
  
  #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
  reference_parameters: Option<ReferenceParametersType>,
  
  #[yaserde(rename = "Metadata", prefix = "wsa")]
  metadata: Option<MetadataType>,
  
  #[yaserde(rename = "RelatesTo", prefix = "wsa")]
  relates_to: Option<RelatesToType>,
  
  #[yaserde(rename = "ProblemHeaderstring", prefix = "wsa")]
  problem_headerstring: Option<String>,
  
  #[yaserde(rename = "ProblemAction", prefix = "wsa")]
  problem_action: Option<ProblemActionType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct EndpointReferenceType
{
  #[yaserde(rename = "Address", prefix = "wsa")]
  address: String,

  #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
  reference_parameters: Option<ReferenceParametersType>,

  #[yaserde(rename = "Metadata", prefix = "wsa")]
  metadata: Option<MetadataType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct ReferenceParametersType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct MetadataType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct RelatesToType
{
  #[yaserde(text)]
  content: String,

  #[yaserde(attribute, rename = "String")]
  relationship_type: Option <String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
struct ProblemActionType
{
  #[yaserde(rename = "Action", prefix = "wsa")]
  action: Option<String>,

  #[yaserde(rename = "SoapAction", prefix = "wsa")]
  soap_action: Option<String>
}

pub fn request_security_token(message: CmcMessage, request_id: impl Into<Option<String>>) -> Envelope<RequestSecurityToken>
{
  Envelope
  {
    header: HeaderType
    {
      reply_to: Some(EndpointReferenceType
        {
          address: "http://www.w3.org/2005/08/addressing/anonymous".to_owned(),
          ..Default::default()
        }),
      action: Some("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep".to_owned()),
      message_id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
      ..Default::default()
    },
    body: BodyType::Body(RequestSecurityToken::new(message, request_id))
  }
}

  /*fn get_policies(t: GetPoliciesType) -> Self
  {
  }*/