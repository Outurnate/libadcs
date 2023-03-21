use cryptographic_message_syntax::{SignedDataBuilder, Oid, Bytes, SignerBuilder, asn1::rfc5652::{SignerIdentifier, IssuerAndSerialNumber, CertificateSerialNumber}, CmsError};
use ring::digest::{digest, SHA256};
use signature::Error;
use x509_certificate::{rfc2986::CertificationRequest, KeyAlgorithm, KeyInfoSigner, Signature, Signer, Sign, SignatureAlgorithm, X509CertificateError, DigestAlgorithm, rfc3280::Name};

use crate::rfc5272::PKIData;

pub fn wrap_in_cmc(request: CertificationRequest) -> Result<Vec<u8>, CmsError>
{
  let subject_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber
    {
      issuer: Name::default(),
      serial_number: CertificateSerialNumber::from(0)
    });
  let csr = PKIData::new(request).encode_der()?;

  SignedDataBuilder::default()
    .content_inline(csr)
    .content_type(Oid(Bytes::from_static(&[43u8, 6u8, 1u8, 5u8, 5u8, 7u8, 12u8, 2u8])))
    .signer(SignerBuilder::new_with_signer_identifier(& NullKeyInfoSigner {}, subject_identifier))
    .build_der()
}

struct NullKeyInfoSigner;

impl KeyInfoSigner for NullKeyInfoSigner {}

impl Signer<Signature> for NullKeyInfoSigner
{
  fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error>
  {
    Ok(digest(&SHA256, msg).as_ref().to_vec().into())
  }
}

impl Sign for NullKeyInfoSigner
{
  fn sign(&self, msg: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError>
  {
    Ok((digest(&SHA256, msg).as_ref().to_vec(), self.signature_algorithm()?))
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
    SignatureAlgorithm::from_oid_and_digest_algorithm(&Oid(Bytes::from_static(&[43, 6, 1, 5, 5, 7, 6, 2])), DigestAlgorithm::Sha256)
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