use std::io::Write;
use auto_enums::auto_enum;
use bcder::{encode::{self, PrimitiveContent}, decode::{Source, Constructed, DecodeError, IntoSource}, Tag, Mode, Integer};
use bcder_derive::Values;
use bytes::Bytes;
use cryptographic_message_syntax::{Oid, asn1::rfc5652::ContentInfo};
use x509_certificate::rfc2986::CertificationRequest;

macro_rules! AnyType
{
  ($name:ident) =>
  {
    #[derive(Clone, Default, Debug)]
    pub struct $name(Bytes);

    #[allow(dead_code)]
    impl $name
    {
      pub fn new(value: Bytes) -> Self
      {
        Self(value)
      }
    
      pub fn from_constructed<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
      {
        cons.take_constructed(|_, cons| Ok(Self(cons.capture_all()?.into_bytes())))
      }
    
      pub fn opt_from_constructed<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>>
      {
        cons.take_opt_constructed(|_, cons| Ok(Self(cons.capture_all()?.into_bytes())))
      }
    
      pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
      {
        Ok(Self(cons.capture_all()?.into_bytes()))
      }
    }
    
    impl encode::Values for $name
    {
      fn encoded_len(&self, mode: Mode) -> usize
      {
        self.0.len()
      }
    
      fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error>
      {
        target.write_all(self.0.as_ref())
      }
    }

    impl PartialEq for $name
    {
      fn eq(&self, other: &Self) -> bool
      {
        self.0 == other.0
      }
    }

    impl Eq for $name {}
  };
}

macro_rules! DeriveValues
{
  ($name:ident) =>
  {
    impl $name
    {
      pub fn encode_ref(&self) -> impl encode::Values + '_
      {
        self.encode_ref_as(self.default_tag())
      }

      pub fn encode_der(&self) -> Result<Vec<u8>, std::io::Error>
      {
        let mut buffer = vec![];
        encode::Values::write_encoded(&self.encode_ref(), Mode::Der, &mut buffer)?;
    
        Ok(buffer)
      }

      pub fn opt_from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>>
      {
        cons.take_opt_sequence(|cons| Self::take_from(cons))
      }
    
      pub fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
      {
        cons.take_sequence(|cons| Self::take_from(cons))
      }

      pub fn decode_der<S: Source, I: IntoSource<Source = S>>(source: I) -> Result<Self, DecodeError<S::Error>>
      {
        Constructed::decode(source, Mode::Der, |cons| Self::from_sequence(cons))
      }
    }

    impl encode::Values for $name
    {
      fn encoded_len(&self, mode: Mode) -> usize
      {
        self.encode_ref().encoded_len(mode)
      }

      fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error>
      {
        self.encode_ref().write_encoded(mode, target)
      }
    }
  };
}

type BodyPartID = Integer;
AnyType!(AttributeValue);
AnyType!(CertificateRequestMessage);
AnyType!(RequestMessage);
AnyType!(OtherMessageValue);

#[derive(Clone)]
pub struct PKIData
{
  pub control_sequence: Vec<TaggedAttribute>,
  pub req_sequence: Vec<TaggedRequest>,
  pub cms_sequence: Vec<TaggedContentInfo>,
  pub other_msg_sequence: Vec<OtherMsg>
}

impl PKIData
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
      (
        encode::sequence(self.control_sequence),
        encode::sequence(self.req_sequence),
        encode::sequence(self.cms_sequence),
        encode::sequence(self.other_msg_sequence)
      ))
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      encode::sequence(&self.control_sequence),
      encode::sequence(&self.req_sequence),
      encode::sequence(&self.cms_sequence),
      encode::sequence(&self.other_msg_sequence)
    ))
  }

  fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let control_sequence = cons.take_sequence(|cons|
    {
      let mut control_sequence = Vec::new();
      while let Some(control) = TaggedAttribute::opt_from_sequence(cons)?
      {
        control_sequence.push(control);
      }
      Ok(control_sequence)
    })?;

    let req_sequence = cons.take_sequence(|cons|
    {
      let mut req_sequence = Vec::new();
      while let Some(req) = TaggedRequest::take_opt_from(cons)?
      {
        req_sequence.push(req);
      }
      Ok(req_sequence)
    })?;

    let cms_sequence = cons.take_sequence(|cons|
    {
      let mut cms_sequence = Vec::new();
      while let Some(cms) = TaggedContentInfo::opt_from_sequence(cons)?
      {
        cms_sequence.push(cms);
      }
      Ok(cms_sequence)
    })?;

    let other_msg_sequence = cons.take_sequence(|cons|
    {
      let mut other_msg_sequence = Vec::new();
      while let Some(other_msg) = OtherMsg::opt_from_sequence(cons)?
      {
        other_msg_sequence.push(other_msg);
      }
      Ok(other_msg_sequence)
    })?;

    Ok(Self
    {
      control_sequence,
      req_sequence,
      cms_sequence,
      other_msg_sequence
    })
  }
}

DeriveValues!(PKIData);

#[derive(Clone)]
pub struct TaggedAttribute
{
  pub body_part_id: BodyPartID,
  pub attr_type: Oid,
  pub attr_values: Vec<AttributeValue>
}

impl TaggedAttribute
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.attr_type.encode_ref(),
      encode::set(&self.attr_values)
    ))
  }

  fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let body_part_id = Integer::take_from(cons)?;
    let attr_type = Oid::take_from(cons)?;
    let attr_values = cons.take_set(|cons|
      {
        let mut attr_values = Vec::new();
        while let Some(attr_value) = AttributeValue::opt_from_constructed(cons)?
        {
          attr_values.push(attr_value);
        }
        Ok(attr_values)
      })?;

    Ok(Self
    {
      body_part_id,
      attr_type,
      attr_values
    })
  }
}

DeriveValues!(TaggedAttribute);

#[derive(Clone)]
pub enum TaggedRequest
{
  TaggedCertificationRequest(TaggedCertificationRequest),
  CertificateRequestMessage(CertificateRequestMessage),
  OtherRequestMessage
  {
     body_part_id: BodyPartID,
     request_message_type: Oid,
     request_message_value: RequestMessage
  }
}

impl TaggedRequest
{
  fn default_tag(&self) -> Tag
  {
    match self
    {
      TaggedRequest::TaggedCertificationRequest(_) => Tag::CTX_0,
      TaggedRequest::CertificateRequestMessage(_) => Tag::CTX_1,
      TaggedRequest::OtherRequestMessage { .. } => Tag::CTX_2,
    }
  }

  #[auto_enum(Values)]
  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    match self
    {
      TaggedRequest::TaggedCertificationRequest(tcr) => tcr.encode_ref_as(tag),
      TaggedRequest::CertificateRequestMessage(crm) => crm,
      TaggedRequest::OtherRequestMessage { body_part_id, request_message_type, request_message_value } => encode::sequence_as(tag, (
        body_part_id.encode(),
        request_message_type.encode(),
        request_message_value
      ))
    }
  }

  fn take_from_with_tag<S: Source>(tag: Tag, cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    match tag
    {
      Tag::CTX_0 => Ok(Self::TaggedCertificationRequest(TaggedCertificationRequest::take_from(cons)?)),
      Tag::CTX_1 => Ok(Self::CertificateRequestMessage(CertificateRequestMessage::take_from(cons)?)),
      _ =>
      {
        let body_part_id = Integer::take_from(cons)?;
        let request_message_type = Oid::take_from(cons)?;
        let request_message_value = RequestMessage::take_from(cons)?;

        Ok(Self::OtherRequestMessage { body_part_id, request_message_type, request_message_value })
      }
    }
  }
}

impl TaggedRequest
{
  pub fn encode_ref(&self) -> impl encode::Values + '_
  {
    self.encode_ref_as(self.default_tag())
  }

  pub fn encode_der(&self) -> Result<Vec<u8>, std::io::Error>
  {
    let mut buffer = Vec::new();
    encode::Values::write_encoded(&self.encode_ref(), Mode::Der, &mut buffer)?;
    Ok(buffer)
  }

  pub fn take_opt_from<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>>
  {
    if let Some(res) = cons.take_opt_constructed_if(Tag::CTX_0, |cons| Self::take_from_with_tag(Tag::CTX_0, cons))?
    {
      Ok(Some(res))
    }
    else if let Some(res) = cons.take_opt_constructed_if(Tag::CTX_1, |cons| Self::take_from_with_tag(Tag::CTX_1, cons))?
    {
      Ok(Some(res))
    }
    else
    {
      cons.take_opt_constructed_if(Tag::CTX_2, |cons| Self::take_from_with_tag(Tag::CTX_2, cons))
    }
  }

  pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    cons.take_constructed(|tag, cons| Self::take_from_with_tag(tag, cons))
  }

  pub fn decode_der<S: Source, I: IntoSource<Source = S>>(source: I) -> Result<Self, DecodeError<S::Error>>
  {
    Constructed::decode(source, Mode::Der, |cons| Self::take_from(cons))
  }
}

impl encode::Values for TaggedRequest
{
  fn encoded_len(&self, mode: Mode) -> usize
  {
    self.encode_ref().encoded_len(mode)
  }

  fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error>
  {
    self.encode_ref().write_encoded(mode, target)
  }
}

#[derive(Clone)]
pub struct TaggedCertificationRequest
{
  pub body_part_id: BodyPartID,
  pub certification_request: CertificationRequest
}

impl TaggedCertificationRequest
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      &self.certification_request
    ))
  }

  fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let body_part_id = Integer::take_from(cons)?;
    let certification_request = CertificationRequest::take_from(cons)?;

    Ok(Self
    {
      body_part_id,
      certification_request
    })
  }
}

DeriveValues!(TaggedCertificationRequest);

#[derive(Clone)]
pub struct TaggedContentInfo
{
  body_part_id: BodyPartID,
  content_info: ContentInfo
}

impl TaggedContentInfo
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      &self.content_info
    ))
  }

  fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let body_part_id = Integer::take_from(cons)?;
    let content_info = cons.take_sequence(|cons| ContentInfo::from_sequence(cons))?;

    Ok(Self
    {
      body_part_id,
      content_info
    })
  }
}

DeriveValues!(TaggedContentInfo);

#[derive(Clone)]
pub struct OtherMsg
{
  body_part_id: BodyPartID,
  other_msg_type: Oid,
  other_msg_value: OtherMessageValue
}

impl OtherMsg
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.other_msg_type.encode_ref(),
      &self.other_msg_value
    ))
  }

  fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let body_part_id = Integer::take_from(cons)?;
    let other_msg_type = Oid::take_from(cons)?;
    let other_msg_value = OtherMessageValue::from_constructed(cons)?;

    Ok(Self
    {
      body_part_id,
      other_msg_type,
      other_msg_value
    })
  }
}

DeriveValues!(OtherMsg);

#[derive(Clone)]
pub struct PKIResponse
{
  pub control_sequence: Vec<TaggedAttribute>,
  pub cms_sequence: Vec<TaggedContentInfo>,
  pub other_msg_sequence: Vec<OtherMsg>
}

impl PKIResponse
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      encode::sequence(&self.control_sequence),
      encode::sequence(&self.cms_sequence),
      encode::sequence(&self.other_msg_sequence)
    ))
  }

  fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    cons.take_sequence(|cons|
    {
      let control_sequence = cons.take_sequence(|cons|
      {
        let mut control_sequence = Vec::new();
        while let Some(control) = TaggedAttribute::opt_from_sequence(cons)?
        {
          control_sequence.push(control);
        }
        Ok(control_sequence)
      })?;

      let cms_sequence = cons.take_sequence(|cons|
      {
        let mut cms_sequence = Vec::new();
        while let Some(cms) = TaggedContentInfo::opt_from_sequence(cons)?
        {
          cms_sequence.push(cms);
        }
        Ok(cms_sequence)
      })?;

      let other_msg_sequence = cons.take_sequence(|cons|
      {
        let mut other_msg_sequence = Vec::new();
        while let Some(other_msg) = OtherMsg::opt_from_sequence(cons)?
        {
          other_msg_sequence.push(other_msg);
        }
        Ok(other_msg_sequence)
      })?;

      Ok(Self
      {
        control_sequence,
        cms_sequence,
        other_msg_sequence
      })
    })
  }
}

DeriveValues!(PKIResponse);