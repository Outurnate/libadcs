pub mod rfc5272;

use std::convert::Infallible;

use bcder::{Mode, decode::{Constructed, DecodeError}};
use cryptographic_message_syntax::{SignedDataBuilder, Oid, Bytes, SignerBuilder, asn1::rfc5652::{SignerIdentifier, IssuerAndSerialNumber, CertificateSerialNumber, self, CertificateChoices}, CmsError, SignedData};
use signature::Error;
use x509_certificate::{rfc2986::CertificationRequest, KeyAlgorithm, KeyInfoSigner, Signature, Signer, Sign, SignatureAlgorithm, X509CertificateError, DigestAlgorithm, rfc3280::Name, X509Certificate};
use self::rfc5272::{AttributeValue, PKIData, PKIResponse};

pub struct CmcMessage(pub(crate) Vec<u8>);

impl CmcMessage
{
  pub fn new(request: CertificationRequest, attributes: impl Iterator<Item = (Oid, Vec<AttributeValue>)>) -> Result<Self, CmsError>
  {
    let subject_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber
      {
        issuer: Name::default(),
        serial_number: CertificateSerialNumber::from(0)
      });
    let csr = PKIData::new(request, attributes).encode_der()?;

    Ok(Self(SignedDataBuilder::default()
      .content_inline(csr)
      .content_type(Oid(Bytes::from_static(&[43u8, 6u8, 1u8, 5u8, 5u8, 7u8, 12u8, 2u8])))
      .signer(SignerBuilder::new_with_signer_identifier(& NullKeyInfoSigner { digest_algorithm: DigestAlgorithm::Sha256 }, subject_identifier))
      .build_der()?))
  }

  pub fn decode(&self) -> Result<Vec<X509Certificate>, DecodeError<Infallible>>
  {
    let signed_data = Constructed::decode(self.0.as_slice(), Mode::Der, |cons| rfc5652::SignedData::decode(cons))?;
    let response = PKIResponse::decode_der(signed_data.content_info.content.unwrap())?;
    Ok(vec![]) // TODO
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests
{
  use base64::{engine::general_purpose, Engine};
  use bcder::{Mode, decode::Constructed};
  use cryptographic_message_syntax::SignedData;
  use x509_certificate::rfc2986::CertificationRequest;

  const CSR: &str = "MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDzANBgNVBAcMBkxpbmRvbjEWMBQGA1UECgwNRGlnaUNlcnQgSW5jLjERMA8GA1UECwwIRGlnaUNlcnQxHTAbBgNVBAMMFGV4YW1wbGUuZGlnaWNlcnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8+To7d+2kPWeBv/orU3LVbJwDrSQbeKamCmowp5bqDxIwV20zqRb7APUOKYoVEFFOEQs6T6gImnIolhbiH6m4zgZ/CPvWBOkZc+c1Po2EmvBz+AD5sBdT5kzGQA6NbWyZGldxRthNLOs1efOhdnWFuhI162qmcflgpiIWDuwq4C9f+YkeJhNn9dF5+owm8cOQmDrV8NNdiTqin8q3qYAHHJRW28glJUCZkTZwIaSR6crBQ8TbYNE0dc+Caa3DOIkz1EOsHWzTx+n0zKfqcbgXi4DJx+C1bjptYPRBPZL8DAeWuA8ebudVT44yEp82G96/Ggcf7F33xMxe0yc+Xa6owIDAQABoAAwDQYJKoZIhvcNAQEFBQADggEBAB0kcrFccSmFDmxox0Ne01UIqSsDqHgL+XmHTXJwre6DhJSZwbvEtOK0G3+dr4Fs11WuUNt5qcLsx5a8uk4G6AKHMzuhLsJ7XZjgmQXGECpYQ4mC3yT3ZoCGpIXbw+iP3lmEEXgaQL0Tx5LFl/okKbKYwIqNiyKWOMj7ZR/wxWg/ZDGRs55xuoeLDJ/ZRFf9bI+IaCUd1YrfYcHIl3G87Av+r49YVwqRDT0VDV7uLgqn29XI1PpVUNCPQGn9p/eX6Qo7vpDaPybRtA2R7XLKjQaF9oXWeCUqy1hvJac9QFO297Ob1alpHPoZ7mWiEuJwjBPii6a9M9G30nUo39lBi1w=";

  #[test]
  fn test_encode()
  {
    //let csr = Constructed::decode(general_purpose::STANDARD.decode(CSR).unwrap().as_slice(), Mode::Der, |cons| CertificationRequest::take_from(cons)).unwrap();
    //println!("{}", general_purpose::STANDARD.encode(wrap_in_cms(csr, vec![].into_iter()).unwrap()));
  }
}