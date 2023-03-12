mod rfc5272;

use base64::{Engine as _, engine::general_purpose};
use bcder::OctetString;
use cryptographic_message_syntax::{SignedDataBuilder, Oid, Bytes, SignerBuilder, asn1::rfc5652::SignerIdentifier};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use x509_certificate::{rfc2986::CertificationRequest, X509CertificateBuilder, KeyAlgorithm, EcdsaCurve, InMemorySigningKeyPair, KeyInfoSigner};

use crate::rfc5272::PKIData;

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
  let digest = digest(&SHA1_FOR_LEGACY_USE_ONLY, &request.certificate_request_info.subject_public_key_info.subject_public_key.octet_bytes());
  let subject_identifier = SignerIdentifier::SubjectKeyIdentifier(OctetString::new(Bytes::copy_from_slice(digest.as_ref())));
  let csr = PKIData::new(request).encode_der().unwrap();

  let cms = SignedDataBuilder::default()
    .content_inline(csr)
    .content_type(Oid(Bytes::from_static(&[43u8, 6u8, 1u8, 5u8, 5u8, 7u8, 12u8, 2u8])))
    .signer(SignerBuilder::new_with_signer_identifier(signer, subject_identifier))
    .build_der().unwrap();
  println!("{}", general_purpose::STANDARD_NO_PAD.encode(cms));
}