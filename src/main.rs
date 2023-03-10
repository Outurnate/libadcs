use base64::{Engine as _, engine::general_purpose};
use bcder::{Captured, encode::{self, PrimitiveContent}, Tag};
use cryptographic_message_syntax::{SignedDataBuilder, Oid, Bytes, SignerBuilder, asn1::rfc5652::ContentInfo};
use x509_certificate::{rfc2986::CertificationRequest, X509CertificateBuilder, KeyAlgorithm, EcdsaCurve, InMemorySigningKeyPair, KeyInfoSigner};

struct PKIData
{
  control_sequence: Vec<TaggedAttribute>,
  req_sequence: Vec<TaggedRequest>,
  cms_sequence: Vec<TaggedContentInfo>,
  other_msg_sequence: Vec<OtherMsg>
}

impl PKIData
{
  pub fn encode(self) -> impl encode::Values
  {
    self.encode_as(Tag::SEQUENCE)
  }

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      encode::set_as(tag, self.control_sequence),
      encode::set_as(tag, self.req_sequence),
      encode::set_as(tag, self.cms_sequence),
      encode::set_as(tag, self.other_msg_sequence)
    ))
  }
}

struct TaggedAttribute
{
  body_part_id: BodyPartID,
  attr_type: Oid,
  attr_values: Vec<Captured>
}

impl encode::Values for TaggedAttribute
{
  fn encode(self) -> impl encode::Values
  {
    self.encode_as(Tag::SEQUENCE)
  }

  fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.attr_type.encode(),
      encode::set_as(tag, self.attr_values)
    ))
  }
}

enum TaggedRequest
{
  TaggedCertificationRequest(TaggedCertificationRequest),
  CertificateRequestMessage(Captured),
  orm
  {
     body_part_id: BodyPartID,
     request_message_type: Oid,
     request_message_value: ()
  }
}

struct TaggedCertificationRequest
{
  body_part_id: BodyPartID,
  certification_request: CertificationRequest
}

impl TaggedCertificationRequest
{
  pub fn encode(self) -> impl encode::Values
  {
    self.encode_as(Tag::SEQUENCE)
  }

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.certification_request.encode()
    ))
  }
}

struct TaggedContentInfo
{
  body_part_id: BodyPartID,
  content_info: ContentInfo
}

impl TaggedContentInfo
{
  pub fn encode(self) -> impl encode::Values
  {
    self.encode_as(Tag::SEQUENCE)
  }

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.content_info.encode()
    ))
  }
}

struct OtherMsg
{
  body_part_id: BodyPartID,
  other_msg_type: Oid,
  other_msg_value: Captured
}

impl OtherMsg
{
  pub fn encode(self) -> impl encode::Values
  {
    self.encode_as(Tag::SEQUENCE)
  }

  pub fn encode_as(self, tag: Tag) -> impl encode::Values
  {
    encode::sequence_as(tag,
    (
      self.body_part_id.encode(),
      self.other_msg_type.encode(),
      self.other_msg_value.encode()
    ))
  }
}

type BodyPartID = i64;

fn main()
{
  let (keypair, _) = InMemorySigningKeyPair::generate_random(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)).unwrap();
  let mut request = X509CertificateBuilder::new(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1));
  request.subject().append_common_name_utf8_string("eggs benedict").unwrap();
  request.create_certificate_signing_request(&keypair).unwrap();

  cms_chew(request.create_certificate_signing_request(&keypair).unwrap(), &keypair);
}

fn cms_chew(request: CertificationRequest, signer: &dyn KeyInfoSigner)
{
  let csr = request.encode_der().unwrap();

  let cms_builder = SignedDataBuilder::default();
  let cms = cms_builder
    .content_inline(csr)
    .content_type(Oid(Bytes::from_static(&[43u8, 6u8, 1u8, 5u8, 5u8, 7u8, 12u8, 2u8])))
    .signer(SignerBuilder::new(signer, &request))
    .build_der().unwrap();
  println!("{}", general_purpose::STANDARD_NO_PAD.encode(cms));
}