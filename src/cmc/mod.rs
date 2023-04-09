pub mod rfc5272;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

use std::fmt::Display;

use bcder::decode::Constructed;
use cryptographic_message_syntax::{SignedDataBuilder, Oid, Bytes, SignerBuilder, asn1::rfc5652::{SignerIdentifier, IssuerAndSerialNumber, CertificateSerialNumber, self, CertificateChoices}, CmsError, SignedData};
use signature::Error;
use x509_certificate::{rfc2986::CertificationRequest, KeyAlgorithm, KeyInfoSigner, Signature, Signer, Sign, SignatureAlgorithm, X509CertificateError, DigestAlgorithm, rfc3280::Name, X509Certificate};
use self::rfc5272::{AttributeValue, PKIData};

pub struct CmcRequest
{
  request: CertificationRequest,
  attributes: Vec<(Oid, Vec<AttributeValue>)>
}

impl CmcRequest
{
  pub fn new(request: CertificationRequest, attributes: impl Iterator<Item = (Oid, Vec<AttributeValue>)>) -> Self
  {
    Self
    {
      request,
      attributes: attributes.collect()
    }
  }
}

impl TryInto<Vec<u8>> for CmcRequest
{
  type Error = CmsError;

  fn try_into(self) -> Result<Vec<u8>, Self::Error>
  {
    let subject_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber
      {
        issuer: Name::default(),
        serial_number: CertificateSerialNumber::from(0)
      });
    let csr = PKIData::new(self.request, self.attributes.into_iter()).encode_der()?;

    SignedDataBuilder::default()
      .content_inline(csr)
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
    let content = signed_data.signed_content().unwrap();
    let pkidata = PKIData::decode_der(content)?;
    let res = Ok(Self
    {
      request: pkidata.get_certificate_requests().next().unwrap().clone(),
      attributes: vec![]
    });
    res
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

/*impl CmcMessage
{

  pub fn decode(&self) -> Result<Vec<X509Certificate>, DecodeError<Infallible>>
  {
    let signed_data = Constructed::decode(self.0.as_slice(), Mode::Der, |cons| rfc5652::SignedData::decode(cons))?;
    let response = PKIResponse::decode_der(signed_data.content_info.content.unwrap())?;
    Ok(vec![]) // TODO
  }
}*/

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