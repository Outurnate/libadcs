use xml_schema_derive::XmlSchema;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wsse.xsd", target_prefix = "wsse")]
pub struct WSSecurityExtensions;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wst.xsd", target_prefix = "wst")]
pub struct WSTrust;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/wstep.xsd", target_prefix = "wstep")]
pub struct WStep;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/xcep.xsd", target_prefix = "xcep")]
pub struct XCEP;

#[derive(Debug, XmlSchema)]
#[xml_schema(source = "src/soap.xsd", target_prefix = "soap")]
pub struct SOAP;