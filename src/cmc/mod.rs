pub mod rfc5272;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

use bcder::{decode::Constructed, Integer};
use cryptographic_message_syntax::{SignedDataBuilder, Oid, Bytes, SignerBuilder, asn1::rfc5652::{SignerIdentifier, IssuerAndSerialNumber, CertificateSerialNumber, self}, CmsError, SignedData};
use signature::Error;
use x509_certificate::{rfc2986::CertificationRequest, KeyAlgorithm, KeyInfoSigner, Signature, Signer, Sign, SignatureAlgorithm, X509CertificateError, DigestAlgorithm, rfc3280::Name, X509Certificate};
use self::rfc5272::{AttributeValue, PKIData, TaggedAttribute, TaggedRequest, TaggedCertificationRequest};
use std::str::FromStr;

struct AttributedCertificationRequest
{
  request: CertificationRequest,
  attributes: Vec<(Oid, Vec<AttributeValue>)>
}

#[derive(Default)]
pub struct CmcRequest
{
  certificate_requests: Vec<AttributedCertificationRequest>
}

#[derive(Default)]
pub struct CmcRequestBuilder(CmcRequest);

impl CmcRequestBuilder
{
  pub fn add_certificate(mut self, request: CertificationRequest, attributes: Vec<(Oid, Vec<AttributeValue>)>) -> Self
  {
    self.0.certificate_requests.push(AttributedCertificationRequest { request, attributes });
    self
  }

  pub fn build(self) -> CmcRequest
  {
    self.0
  }
}

impl TryInto<Vec<u8>> for CmcRequest
{
  type Error = CmsError;

  fn try_into(self) -> Result<Vec<u8>, Self::Error>
  {
    let mut control_sequence = Vec::new();
    let mut req_sequence = Vec::new();
    for (body_part_id, AttributedCertificationRequest { request, attributes }) in self.certificate_requests.into_iter().enumerate()
    {
      let body_part_id = Integer::from(body_part_id as u64);
      req_sequence.push(TaggedRequest::TaggedCertificationRequest(TaggedCertificationRequest { body_part_id: body_part_id.clone(), certification_request: request }));
      for (attr_type, attr_values) in attributes
      {
        control_sequence.push(TaggedAttribute { body_part_id: body_part_id.clone(), attr_type, attr_values })
      }
    }

    let pkidata = PKIData
    {
      control_sequence,
      req_sequence,
      cms_sequence: vec![],
      other_msg_sequence: vec![]
    }.encode_der()?;

    let subject_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber
      {
        issuer: Name::default(),
        serial_number: CertificateSerialNumber::from(0)
      });
    SignedDataBuilder::default()
      .content_inline(pkidata)
      .content_type(Oid(Bytes::from_static(&[43u8, 6u8, 1u8, 5u8, 5u8, 7u8, 12u8, 2u8])))
      .signer(SignerBuilder::new_with_signer_identifier(&NullKeyInfoSigner { digest_algorithm: DigestAlgorithm::Sha256 }, subject_identifier))
      .build_der()
  }
}

impl TryFrom<Vec<u8>> for CmcRequest
{
  type Error = CmsError;

  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
  {
    let signed_data = SignedData::parse_der(value.as_slice())?;
    if let Some(content) = signed_data.signed_content()
    {
      let pkidata = PKIData::decode_der(content)?;

      let certificate_requests = pkidata.req_sequence.into_iter().filter_map(|request|
      {
        if let TaggedRequest::TaggedCertificationRequest(request) = request
        {
          let attributes = pkidata.control_sequence
            .iter()
            .filter(|control| control.body_part_id == request.body_part_id)
            .map(|tagged| (tagged.attr_type.clone(), tagged.attr_values.clone()))
            .collect();
          let request = request.certification_request;

          Some(AttributedCertificationRequest { attributes, request })
        }
        else
        {
          None
        }
      }).collect();

      Ok(CmcRequest { certificate_requests })
    }
    else
    {
      Ok(CmcRequest::default())
    }
  }
}

pub struct CmcResponse
{
  certificates: Vec<X509Certificate>
}

impl CmcResponse
{
  fn get_certificates(&self) -> impl Iterator<Item = &'_ X509Certificate>
  {
    self.certificates.iter()
  }
}

impl TryInto<Vec<u8>> for CmcResponse
{
  type Error = CmsError;

  fn try_into(self) -> Result<Vec<u8>, Self::Error>
  {
    todo!()
  }
}

impl TryFrom<Vec<u8>> for CmcResponse
{
  type Error = CmsError;

  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
  {
    todo!()
  }
}

trait SignedDataExt<'a>: TryFrom<&'a rfc5652::SignedData>
{
  fn parse_der(data: &[u8]) -> Result<Self, CmsError>;
}

impl<'a> SignedDataExt<'a> for SignedData
{
  fn parse_der(data: &[u8]) -> Result<Self, CmsError>
  {
    SignedData::try_from(&Constructed::decode(data, bcder::Mode::Der, |cons| rfc5652::SignedData::decode(cons))?)
  }
}

struct NullKeyInfoSigner
{
  digest_algorithm: DigestAlgorithm
}

impl NullKeyInfoSigner
{
  fn digest(&self, data: &[u8]) -> Vec<u8>
  {
    let mut digester = self.digest_algorithm.digester();
    digester.update(data);
    digester.finish().as_ref().to_vec()
  }
}

impl KeyInfoSigner for NullKeyInfoSigner {}

impl Signer<Signature> for NullKeyInfoSigner
{
  fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error>
  {
    Ok(self.digest(msg).into())
  }
}

impl Sign for NullKeyInfoSigner
{
  fn sign(&self, msg: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError>
  {
    Ok((self.digest(msg), self.signature_algorithm()?))
  }

  fn key_algorithm(&self) -> Option<KeyAlgorithm>
  {
    unimplemented!()
  }

  fn public_key_data(&self) -> Bytes
  {
    unimplemented!()
  }

  fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError>
  {
    Ok(SignatureAlgorithm::from_digest_algorithm(self.digest_algorithm))
  }

  fn private_key_data(&self) -> Option<Vec<u8>>
  {
    unimplemented!()
  }

  fn rsa_primes(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, X509CertificateError>
  {
    unimplemented!()
  }
}

pub trait OidExt
{
  fn parse(value: &str) -> Result<Oid, &'static str>;
}

fn from_str(s: &str) -> Result<u32, &'static str>
{
  u32::from_str(s).map_err(|_| "only integer components allowed")
}

impl OidExt for Oid
{
  fn parse(value: &str) -> Result<Oid, &'static str>
  {
    let mut components = value.split('.');
    let (first, second) = match (components.next(), components.next())
    {
      (Some(first), Some(second)) => (first, second),
      _ => { return Err("at least two components required"); }
    };

    let first = from_str(first)?;
    if first > 2
    {
      return Err("first component can only be 0, 1, or 2.")
    }

    let second = from_str(second)?;
    if first < 2 && second >= 40
    {
      return Err("second component for 0. and 1. must be less than 40");
    }

    let mut res = vec![40 * first + second];
    for item in components
    {
      res.push(from_str(item)?);
    }

    let mut bytes = vec![];
    for item in res
    {
      if item > 0x0FFF_FFFF
      {
        bytes.push(((item >> 28) | 0x80) as u8);
      }
      if item > 0x001F_FFFF
      {
        bytes.push((((item >> 21) & 0x7F) | 0x80) as u8);
      }
      if item > 0x0000_3FFF
      {
        bytes.push((((item >> 14) & 0x7F) | 0x80) as u8)
      }
      if item > 0x0000_007F
      {
        bytes.push((((item >> 7) & 0x7F) | 0x80) as u8);
      }
      bytes.push((item & 0x7F) as u8);
    }

    Ok(Oid(bytes.into()))
  }
}