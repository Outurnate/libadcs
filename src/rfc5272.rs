use std::{ops::{DerefMut, Deref}, io::Write};
use auto_enums::auto_enum;
use bcder::{Captured, encode::{self, PrimitiveContent, Values, sequence_as, set_as, sequence, set}, Tag, Mode};
use bcder_derive::Values;
use cryptographic_message_syntax::{Oid, asn1::rfc5652::ContentInfo};
use x509_certificate::rfc2986::CertificationRequest;

macro_rules! CapturedType
{
  ($name:ident) =>
  {
    #[derive(Clone)]
    struct $name(Captured);

    impl Values for $name
    {
      fn encoded_len(&self, mode: Mode) -> usize
      {
        self.0.encoded_len(mode)
      }

      fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error>
      {
        self.0.write_encoded(mode, target)
      }
    }

    impl Deref for $name
    {
      type Target = Captured;

      fn deref(&self) -> &Self::Target
      {
        &self.0
      }
    }

    impl DerefMut for $name
    {
      fn deref_mut(&mut self) -> &mut Self::Target
      {
        &mut self.0
      }
    }

    impl PartialEq for $name
    {
      fn eq(&self, other: &Self) -> bool
      {
        self.0.as_slice() == other.0.as_slice()
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
      pub fn encode(self) -> impl Values
      {
        let tag = self.default_tag();
        self.encode_as(tag)
      }
      
      pub fn encode_ref(&self) -> impl Values + '_
      {
        self.encode_ref_as(self.default_tag())
      }

      pub fn encode_der(&self) -> Result<Vec<u8>, std::io::Error>
      {
        let mut buffer = vec![];
        self.clone().encode().write_encoded(Mode::Der, &mut buffer)?;
    
        Ok(buffer)
      }
    }

    impl Values for $name
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

CapturedType!(AttributeValue);
CapturedType!(CertificateRequestMessage);
CapturedType!(RequestMessage);
CapturedType!(OtherMessageValue);

#[derive(Clone)]
pub struct PKIData
{
  control_sequence: Vec<TaggedAttribute>,
  req_sequence: Vec<TaggedRequest>,
  cms_sequence: Vec<TaggedContentInfo>,
  other_msg_sequence: Vec<OtherMsg>
}

impl PKIData
{
  pub fn new(request: CertificationRequest) -> Self
  {
    Self
    {
      control_sequence: vec![],
      req_sequence: vec![TaggedRequest::TaggedCertificationRequest(TaggedCertificationRequest
      {
        body_part_id: 1,
        certification_request: request
      })],
      cms_sequence: vec![],
      other_msg_sequence: vec![]
    }
  }
}

impl PKIData
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_as(self, tag: Tag) -> impl Values
  {
    sequence_as(tag,
      (
        set(self.control_sequence),
        set(self.req_sequence),
        set(self.cms_sequence),
        set(self.other_msg_sequence)
      ))
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_
  {
    sequence_as(tag,
    (
      set(&self.control_sequence),
      set(&self.req_sequence),
      set(&self.cms_sequence),
      set(&self.other_msg_sequence)
    ))
  }
}

DeriveValues!(PKIData);

#[derive(Clone)]
struct TaggedAttribute
{
  body_part_id: BodyPartID,
  attr_type: Oid,
  attr_values: Vec<AttributeValue>
}

impl TaggedAttribute
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_as(self, tag: Tag) -> impl Values
  {
    sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.attr_type.encode(),
      set(self.attr_values)
    ))
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_
  {
    sequence_as(tag,
    (
      self.body_part_id.encode_ref(),
      self.attr_type.encode_ref(),
      set(&self.attr_values)
    ))
  }
}

DeriveValues!(TaggedAttribute);

#[derive(Clone)]
enum TaggedRequest
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
  pub fn encode_as(self, tag: Tag) -> impl Values
  {
    match self
    {
      TaggedRequest::TaggedCertificationRequest(tcr) => tcr.encode_as(tag),
      TaggedRequest::CertificateRequestMessage(crm) => crm,
      TaggedRequest::OtherRequestMessage { body_part_id, request_message_type, request_message_value } => sequence_as(tag, (
        body_part_id.encode(),
        request_message_type.encode(),
        request_message_value
      ))
    }
  }

  #[auto_enum(Values)]
  pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_
  {
    match self
    {
      TaggedRequest::TaggedCertificationRequest(tcr) => tcr.encode_ref_as(tag),
      TaggedRequest::CertificateRequestMessage(crm) => crm,
      TaggedRequest::OtherRequestMessage { body_part_id, request_message_type, request_message_value } => sequence_as(tag, (
        body_part_id.encode(),
        request_message_type.encode(),
        request_message_value
      ))
    }
  }
}

DeriveValues!(TaggedRequest);

#[derive(Clone)]
struct TaggedCertificationRequest
{
  body_part_id: BodyPartID,
  certification_request: CertificationRequest
}

impl TaggedCertificationRequest
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub fn encode_as(self, tag: Tag) -> impl Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.certification_request
    ))
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode_ref(),
      &self.certification_request
    ))
  }
}

DeriveValues!(TaggedCertificationRequest);

#[derive(Clone)]
struct TaggedContentInfo
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

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.content_info
    ))
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode_ref(),
      &self.content_info
    ))
  }
}

DeriveValues!(TaggedContentInfo);

#[derive(Clone)]
struct OtherMsg
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

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.other_msg_type.encode(),
      self.other_msg_value
    ))
  }

  pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode_ref(),
      self.other_msg_type.encode_ref(),
      &self.other_msg_value
    ))
  }
}

DeriveValues!(OtherMsg);

type BodyPartID = i64;