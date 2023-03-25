use std::ptr::null_mut;
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::{RpcBinding, Protocol, RpcError, DceString, clone_to_utf16, clone_to_utf16_le};

bitflags!
{
  #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
  pub struct DWFlags: u32
  {
    const CERTIFICATE_TRANSPARENCY                       = 0b0000_0100_0000_0000_0000_0000_0000_0000;
    const PRE_SIGN_CERTIFICATE_REQUEST                   = 0b0000_1000_0000_0000_0000_0000_0000_0000;
    const INCLUDE_CRLS                                   = 0b0000_0000_0000_1000_0000_0000_0000_0000;
    const CMC_FULL_PKI_RESPONSE                          = 0b0000_0000_0000_0100_0000_0000_0000_0000;
    const RENEW_ON_BEHALF_OF                             = 0b0000_0000_0010_0000_0000_0000_0000_0000;
    const REQUEST_TYPE_CA_DETERMINES                     = 0b0000_0000_0000_0000_0000_0000_0000_0000;
    const REQUEST_TYPE_PKCS_10                           = 0b0000_0000_0000_0000_0000_0001_0000_0000;
    const REQUEST_TYPE_NETSCAPE_KEYGEN                   = 0b0000_0000_0000_0000_0000_0010_0000_0000;
    const REQUEST_TYPE_CMS                               = 0b0000_0000_0000_0000_0000_0011_0000_0000;
    const REQUEST_TYPE_CMC                               = 0b0000_0000_0000_0000_0000_0100_0000_0000;
    const REQUEST_TYPE_CA_CHALLENGE_RESPONSE             = 0b0000_0000_0000_0000_0000_0101_0000_0000;
    const REQUEST_TYPE_SIGNED_CERTIFICATE_TIMESTAMP_LIST = 0b0000_0000_0000_0000_0000_0110_0000_0000;
  }
}

pub struct CertificateServerResponse
{
  pub request_id: Option<u32>,
  pub disposition: Option<u32>,
  pub certificate_chain: Option<Vec<u8>>,
  pub entity_certificate: Option<Vec<u8>>,
  pub disposition_message: Option<String>
}

pub struct CertPassage
{
  binding: RpcBinding
}

impl CertPassage
{
  pub fn new(protocol: Protocol, netaddr: &str, spn: &str) -> Result<Self, RpcError>
  {
    let mut binding =
    {
      let binding_string = DceString::compose_binding(protocol, netaddr)?;
      RpcBinding::new(binding_string)
    }?;
    unsafe { binding.ep_resolve(libdcerpc_sys::ICertPassage_v0_0_c_ifspec)?; }
    binding.set_auth_info(spn)?;
    Ok(Self { binding })
  }

  pub fn cert_server_request(&mut self, dw_flags: DWFlags, authority: &str, request_id: Option<u32>, attributes: &str, request: &[u8]) -> CertificateServerResponse
  {
    let mut authority = clone_to_utf16(authority, true);
    let disposition = null_mut(); // out
    let mut attributes = clone_to_utf16_le(attributes, false);
    let mut attributes_blob = libdcerpc_sys::CERTTRANSBLOB { cb: attributes.len() as u32, pb: attributes.as_mut_ptr() };
    let mut request = request.to_owned();
    let mut request_blob = libdcerpc_sys::CERTTRANSBLOB { cb: request.len() as u32, pb: request.as_mut_ptr() };
    let certificate_chain = null_mut(); //out
    let entity_certificate = null_mut(); //out
    let disposition_message = null_mut(); //out
    let request_id = match request_id
    {
      Some(request_id) => request_id as *mut u32,
      None => null_mut(),
    };
    unsafe
    {
      libdcerpc_sys::CertServerRequest(
        self.binding.handle,
        dw_flags.bits(),
        authority.as_mut_ptr(),
        request_id,
        disposition,
        &mut attributes_blob,
        &mut request_blob,
        certificate_chain,
        entity_certificate,
        disposition_message);
      CertificateServerResponse
      {
        request_id: request_id.as_ref().map(|x| x.to_owned()),
        disposition: disposition.as_ref().map(|x| x.to_owned()),
        certificate_chain: certificate_chain.as_ref().map(|x| Vec::from_raw_parts(x.pb, x.cb as usize, x.cb as usize)),
        entity_certificate: entity_certificate.as_ref().map(|x| Vec::from_raw_parts(x.pb, x.cb as usize, x.cb as usize)),
        disposition_message: disposition_message
          .as_ref()
          .map(|x|
            {
              let data = Vec::from_raw_parts(x.pb, x.cb as usize, x.cb as usize);
              String::from_utf16_lossy(data.windows(2).skip(1).map(|mut c| c.read_u16::<LittleEndian>().unwrap()).collect::<Vec<u16>>().as_slice())
            })
      }
    }
  }
}