use std::{ops::{DerefMut, Deref}, io::Write};
use auto_enums::auto_enum;
use bcder::{Captured, encode::{self, PrimitiveContent}, decode::{Source, Constructed, DecodeError, IntoSource}, Tag, Mode, Integer};
use bcder_derive::Values;
use cryptographic_message_syntax::{Oid, asn1::rfc5652::ContentInfo};
use x509_certificate::rfc2986::CertificationRequest;

macro_rules! AnyType
{
  ($name:ident) =>
  {
    #[derive(Clone)]
    pub(crate) struct $name(Captured);

    impl $name
    {
      pub(crate) fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
      {
        cons.take_constructed(|_, cons| Ok(Self(cons.capture_all()?)))
      }

      pub(crate) fn take_opt_from<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>>
      {
        cons.take_opt_constructed(|_, cons| Ok(Self(cons.capture_all()?)))
      }
    }

    impl encode::Values for $name
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
      pub(crate) fn encode_ref(&self) -> impl encode::Values + '_
      {
        self.encode_ref_as(self.default_tag())
      }

      pub(crate) fn encode_der(&self) -> Result<Vec<u8>, std::io::Error>
      {
        let mut buffer = vec![];
        encode::Values::write_encoded(&self.encode_ref(), Mode::Der, &mut buffer)?;
    
        Ok(buffer)
      }

      pub(crate) fn take_opt_from<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>>
      {
        cons.take_opt_sequence(|cons| Self::take(cons))
      }
    
      pub(crate) fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
      {
        cons.take_sequence(|cons| Self::take(cons))
      }

      pub(crate) fn decode_der<S: Source, I: IntoSource<Source = S>>(source: I) -> Result<Self, DecodeError<S::Error>>
      {
        Constructed::decode(source, Mode::Der, |cons| Self::take_from(cons))
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
pub(crate) struct PKIData
{
  control_sequence: Vec<TaggedAttribute>,
  req_sequence: Vec<TaggedRequest>,
  cms_sequence: Vec<TaggedContentInfo>,
  other_msg_sequence: Vec<OtherMsg>
}

impl PKIData
{
  pub(crate) fn new(request: CertificationRequest, attributes: impl Iterator<Item = (Oid, Vec<AttributeValue>)>) -> Self
  {
    let body_part_id = Integer::from(1);
    Self
    {
      control_sequence: attributes.map(|attribute| TaggedAttribute { body_part_id: body_part_id.clone(), attr_type: attribute.0, attr_values: attribute.1 }).collect(),
      req_sequence: vec![TaggedRequest::TaggedCertificationRequest(TaggedCertificationRequest
      {
        body_part_id,
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

  pub(crate) fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
      (
        encode::sequence(self.control_sequence),
        encode::sequence(self.req_sequence),
        encode::sequence(self.cms_sequence),
        encode::sequence(self.other_msg_sequence)
      ))
  }

  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      encode::sequence(&self.control_sequence),
      encode::sequence(&self.req_sequence),
      encode::sequence(&self.cms_sequence),
      encode::sequence(&self.other_msg_sequence)
    ))
  }

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    cons.take_sequence(|cons|
    {
      let control_sequence = cons.take_sequence(|cons|
      {
        let mut control_sequence = Vec::new();
        while let Some(control) = TaggedAttribute::take_opt_from(cons)?
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
        while let Some(cms) = TaggedContentInfo::take_opt_from(cons)?
        {
          cms_sequence.push(cms);
        }
        Ok(cms_sequence)
      })?;

      let other_msg_sequence = cons.take_sequence(|cons|
      {
        let mut other_msg_sequence = Vec::new();
        while let Some(other_msg) = OtherMsg::take_opt_from(cons)?
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
    })
  }
}

DeriveValues!(PKIData);

#[derive(Clone)]
pub(crate) struct TaggedAttribute
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

  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.attr_type.encode_ref(),
      encode::set(&self.attr_values)
    ))
  }

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let body_part_id = Integer::take_from(cons)?;
    let attr_type = Oid::take_from(cons)?;
    let attr_values = cons.take_set(|cons|
      {
        let mut attr_values = Vec::new();
        while let Some(attr_value) = AttributeValue::take_opt_from(cons)?
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
pub(crate) enum TaggedRequest
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
  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
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

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    if let Some(tcr) = cons.take_opt_constructed_if(Tag::CTX_0, |cons| TaggedCertificationRequest::take_from(cons))?
    {
      Ok(Self::TaggedCertificationRequest(tcr))
    }
    else if let Some(crm) = cons.take_opt_constructed_if(Tag::CTX_1, |cons| CertificateRequestMessage::take_from(cons))?
    {
      Ok(Self::CertificateRequestMessage(crm))
    }
    else
    {
      cons.take_sequence(|cons|
      {
        let body_part_id = Integer::take_from(cons)?;
        let request_message_type = Oid::take_from(cons)?;
        let request_message_value = RequestMessage::take_from(cons)?;

        Ok(Self::OtherRequestMessage { body_part_id, request_message_type, request_message_value })
      })
    }
  }
}

DeriveValues!(TaggedRequest);

#[derive(Clone)]
pub(crate) struct TaggedCertificationRequest
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

  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      &self.certification_request
    ))
  }

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
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
pub(crate) struct TaggedContentInfo
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

  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      &self.content_info
    ))
  }

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
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
pub(crate) struct OtherMsg
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

  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.other_msg_type.encode_ref(),
      &self.other_msg_value
    ))
  }

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    let body_part_id = Integer::take_from(cons)?;
    let other_msg_type = Oid::take_from(cons)?;
    let other_msg_value = OtherMessageValue::take_from(cons)?;

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
pub(crate) struct PKIResponse
{
  pub(crate) control_sequence: Vec<TaggedAttribute>,
  pub(crate) cms_sequence: Vec<TaggedContentInfo>,
  pub(crate) other_msg_sequence: Vec<OtherMsg>
}

impl PKIResponse
{
  fn default_tag(&self) -> Tag
  {
    Tag::SEQUENCE
  }

  pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_
  {
    encode::sequence_as(tag,
    (
      encode::sequence(&self.control_sequence),
      encode::sequence(&self.cms_sequence),
      encode::sequence(&self.other_msg_sequence)
    ))
  }

  fn take<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>>
  {
    cons.take_sequence(|cons|
    {
      let control_sequence = cons.take_sequence(|cons|
      {
        let mut control_sequence = Vec::new();
        while let Some(control) = TaggedAttribute::take_opt_from(cons)?
        {
          control_sequence.push(control);
        }
        Ok(control_sequence)
      })?;

      let cms_sequence = cons.take_sequence(|cons|
      {
        let mut cms_sequence = Vec::new();
        while let Some(cms) = TaggedContentInfo::take_opt_from(cons)?
        {
          cms_sequence.push(cms);
        }
        Ok(cms_sequence)
      })?;

      let other_msg_sequence = cons.take_sequence(|cons|
      {
        let mut other_msg_sequence = Vec::new();
        while let Some(other_msg) = OtherMsg::take_opt_from(cons)?
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