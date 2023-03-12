use xml_schema_derive::XmlSchema;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wsse.xsd", target_prefix = "wsse",
  module_namespace_mapping = "crate::schemas::ws_security_extensions::types"
)]
struct WSSecurityExtensions;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wstep.xsd", target_prefix = "wstep",
  module_namespace_mapping = "crate::schemas::ws_tep::types"
)]
struct WSTep;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wst.xsd", target_prefix = "wst",
  module_namespace_mapping = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd: crate::schemas::ws_security_extensions::types",
  module_namespace_mapping = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment: crate::schemas::ws_tep::types",
  module_namespace_mapping = "crate::schemas::ws_trust::types"
)]
struct WSTrust;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/xcep.xsd", target_prefix = "xcep",
  module_namespace_mapping = "crate::schemas::xcep::types"
)]
struct XCEP;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wsa.xsd", target_prefix = "wsa",
  module_namespace_mapping = "crate::schemas::wsa::types"
)]
struct WSA;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/soap-core.xsd", target_prefix = "soap",
  module_namespace_mapping = "http://www.w3.org/2005/08/addressing: crate::schemas::wsa::types"
)]
struct SOAPCore;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/soap-xcep.xsd", target_prefix = "soap",
  module_namespace_mapping = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy: crate::schemas::xcep::types",
  module_namespace_mapping = "http://www.w3.org/2005/08/addressing: crate::schemas::wsa::types"
)]
struct SOAPXcep;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/soap-wst.xsd", target_prefix = "soap",
  module_namespace_mapping = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/: crate::schemas::ws_trust::types",
  module_namespace_mapping = "http://www.w3.org/2005/08/addressing: crate::schemas::wsa::types"
)]
struct SOAPWst;

pub(crate) use ws_security_extensions::types::*;
pub(crate) use ws_security_extensions::*;
pub(crate) use ws_tep::types::*;
pub(crate) use ws_tep::*;
pub(crate) use ws_trust::types::*;
pub(crate) use ws_trust::*;
pub(crate) use xcep::types::*;
pub(crate) use xcep::*;
pub(crate) use wsa::types::*;
pub(crate) use wsa::*;
pub(crate) use soap_core::types::*;
pub(crate) use soap_core::*;
pub(crate) use soap_xcep::types::*;
pub(crate) use soap_xcep::*;
pub(crate) use soap_wst::types::*;
pub(crate) use soap_wst::*;