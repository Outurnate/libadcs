use base64::{engine::general_purpose, Engine};
use x509_certificate::{X509CertificateBuilder, InMemorySigningKeyPair, KeyAlgorithm, rfc2986::CertificationRequest};

use super::CmcRequest;

#[test]
fn request_encode()
{
  let mut builder = X509CertificateBuilder::new(KeyAlgorithm::Ed25519);
  builder.subject().append_common_name_utf8_string("tempuri.org").expect("error setting subject");
  builder.issuer().append_common_name_utf8_string("tempuri.org").expect("error setting issuer");
  let csr = builder.create_certificate_signing_request(&InMemorySigningKeyPair::generate_random(KeyAlgorithm::Ed25519).expect("failed to generate new key pair").0).expect("failed to generate csr");
  let request = CmcRequest::new(csr, vec![].into_iter());
  println!("{}", general_purpose::STANDARD.encode::<Vec<u8>>(request.try_into().expect("failed to build cms message")));
}

#[test]
fn request_decode()
{
  let request = include_str!("valid.txt");
  let request = CmcRequest::try_from(general_purpose::STANDARD.decode(request).expect("error base64 decoding known good cmc")).expect("error decoding known good cmc");
  println!("{}", request.request.encode_pem().expect("failed to encode pem"));
}