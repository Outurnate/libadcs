use chrono::{DateTime, Local};
use tracing::{event, Level, instrument};
use x509_certificate::X509Certificate;
use yaserde_derive::{YaDeserialize, YaSerialize};
use base64::{Engine as _, engine::general_purpose};

use crate::{NamedCertificate, DecodeError, client::{EnrollmentService, Policy}};

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Client
{
  #[yaserde(rename = "lastUpdate", prefix = "xcep")]
  last_update: Option<String>,

  #[yaserde(rename = "preferredLanguage", prefix = "xcep")]
  preferred_language: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct GetPoliciesRequest
{
  #[yaserde(rename = "client", prefix = "xcep")]
  client: Option<Client>,

  #[yaserde(rename = "requestFilter", prefix = "xcep")]
  request_filter: Option<RequestFilter>
}

impl GetPoliciesRequest
{
  pub fn new(last_update: DateTime<Local>) -> Self
  {
    Self
    {
      client: Some(Client
      {
        last_update: Some(last_update.format("%+").to_string()),
        ..Default::default()
      }),
      request_filter: None
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct RequestFilter
{
  #[yaserde(rename = "policyOIDs", prefix = "xcep")]
  policy_oi_ds: PolicyOiDsType,

  #[yaserde(rename = "clientVersion", prefix = "xcep")]
  client_version: i32,

  #[yaserde(rename = "serverVersion", prefix = "xcep")]
  server_version: i32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct PolicyOiDsType
{
  #[yaserde(rename = "oid", prefix = "xcep")]
  oids: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct GetPoliciesResponse
{
  #[yaserde(rename = "response", prefix = "xcep")]
  response: Response,

  #[yaserde(rename = "cAs", prefix = "xcep")]
  certificate_authorities: CertificateAuthorities,

  #[yaserde(rename = "oIDs", prefix = "xcep")]
  oids: OiDsType
}

impl GetPoliciesResponse
{
  #[instrument]
  pub fn into_policy(self, root_certificates: Vec<NamedCertificate>) -> Policy<CertificateAuthorityEndpoints>
  {
    let templates: Vec<_> = self.response.templates.templates
      .into_iter()
      .map(|template|
      {
        let permission = template.attributes.permission.unwrap_or_default();
        (template.certificate_authorities.ids, crate::client::CertificateTemplate
        {
          cn: template.attributes.common_name,
          enroll: permission.enroll,
          auto_enroll: permission.auto_enroll
        })
      })
      .collect();
    let enrollment_services = self.certificate_authorities.cas
      .into_iter()
      .map(|ca|
      {
        let certificate = X509Certificate::from_der(general_purpose::STANDARD.decode(ca.certificate)?)?;
        let nickname = certificate.subject_common_name().unwrap_or_default();
        let certificate = NamedCertificate { nickname, certificate };
        Ok(EnrollmentService
        {
          endpoint: ca.endpoints.unwrap_or_default(),
          certificate,
          template_names: templates
            .iter()
            .filter(|template| template.0.iter().any(|id| *id == ca.reference_id))
            .map(|template| template.1.cn.to_string()).collect()
        })
      })
      .filter_map(|r| r.map_err(|e: DecodeError| event!(Level::WARN, "invalid enrollment service: {}", e)).ok())
      .collect();
    Policy
    {
      enrollment_services,
      templates: templates.into_iter().map(|template| template.1).collect(),
      root_certificates
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Response
{
  #[yaserde(rename = "policyID", prefix = "xcep")]
  policy_id: Option<String>,

  #[yaserde(rename = "policyFriendlyName", prefix = "xcep")]
  policy_friendly_name: String,

  #[yaserde(rename = "nextUpdateHours", prefix = "xcep")]
  next_update_hours: u32,

  #[yaserde(rename = "policiesNotChanged", prefix = "xcep")]
  policies_not_changed: bool,

  #[yaserde(rename = "policies", prefix = "xcep")]
  templates: CertificateTemplates
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateTemplates
{
  #[yaserde(rename = "policy", prefix = "xcep")]
  templates: Vec<CertificateTemplate>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateTemplate
{
  #[yaserde(rename = "policyOIDReference", prefix = "xcep")]
  policy_oid_reference: i32,

  #[yaserde(rename = "cAs", prefix = "xcep")]
  certificate_authorities: CertificateAuthorityReferences,

  #[yaserde(rename = "attributes", prefix = "xcep")]
  attributes: Attributes
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateAuthorityReferences
{
  #[yaserde(rename = "cAReference", prefix = "xcep")]
  ids: Vec<i32>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace ="xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Attributes
{
  #[yaserde(rename = "commonName", prefix = "xcep")]
  common_name: String,

  #[yaserde(rename = "policySchema", prefix = "xcep")]
  policy_schema: u32,

  #[yaserde(rename = "certificateValidity", prefix = "xcep")]
  certificate_validity: Option<CertificateValidity>,

  #[yaserde(rename = "permission", prefix = "xcep")]
  permission: Option<EnrollmentPermission>,

  #[yaserde(rename = "privateKeyAttributes", prefix = "xcep")]
  private_key_attributes: Option<PrivateKeyAttributes>,

  #[yaserde(rename = "revision", prefix = "xcep")]
  revision: Option <Revision>,

  #[yaserde(rename = "supersededPolicies", prefix = "xcep")]
  superseded_policies: CommonNamesType,

  #[yaserde(rename = "privateKeyFlags", prefix = "xcep")]
  private_key_flags: u32,

  #[yaserde(rename = "subjectNameFlags", prefix = "xcep")]
  subject_name_flags: u32,

  #[yaserde(rename = "enrollmentFlags", prefix = "xcep")]
  enrollment_flags: u32,

  #[yaserde(rename = "generalFlags", prefix = "xcep")]
  general_flags: u32,

  #[yaserde(rename = "hashAlgorithmOIDReference", prefix = "xcep")]
  hash_algorithm_oid_reference: i32,

  #[yaserde(rename = "rARequirements", prefix = "xcep")]
  r_a_requirements: RaRequirements,

  #[yaserde(rename = "keyArchivalAttributes", prefix = "xcep")]
  key_archival_attributes: KeyArchivalAttributes,

  #[yaserde(rename = "extensions", prefix = "xcep")]
  extensions: ExtensionsType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateValidity
{
  #[yaserde(rename = "validityPeriodSeconds", prefix = "xcep")]
  validity_period_seconds : u64,

  #[yaserde(rename = "renewalPeriodSeconds", prefix = "xcep")]
  renewal_period_seconds : u64
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct EnrollmentPermission
{
  #[yaserde(rename = "enroll", prefix = "xcep")]
  enroll: bool,

  #[yaserde(rename = "autoEnroll", prefix = "xcep")]
  auto_enroll: bool
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct PrivateKeyAttributes
{
  #[yaserde(rename = "minimalKeyLength", prefix = "xcep")]
  minimal_key_length: u32,

  #[yaserde(rename = "keySpec", prefix = "xcep")]
  key_spec: u32,
  
  #[yaserde(rename = "keyUsageProperty", prefix = "xcep")]
  key_usage_property: u32,

  #[yaserde(rename = "permissions", prefix = "xcep")]
  permissions: String,

  #[yaserde(rename = "algorithmOIDReference", prefix = "xcep")]
  algorithm_oid_reference: i32,

  #[yaserde(rename = "cryptoProviders", prefix = "xcep")]
  crypto_providers: ProvidersType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct ProvidersType
{
  #[yaserde(rename = "provider", prefix = "xcep")]
  providers: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Revision
{
  #[yaserde(rename = "majorRevision", prefix = "xcep")]
  major_revision: u32,

  #[yaserde(rename = "minorRevision", prefix = "xcep")]
  minor_revision: u32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CommonNamesType
{
  #[yaserde(rename = "commonName", prefix = "xcep")]
  common_names: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct RaRequirements
{
  #[yaserde(rename = "rASignatures", prefix = "xcep")]
  r_a_signatures: u32,

  #[yaserde(rename = "rAEKUs", prefix = "xcep")]
  r_aek_us: OidReferencesType,

  #[yaserde(rename = "rAPolicies", prefix = "xcep")]
  r_a_policies: OidReferencesType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct OidReferencesType
{
  #[yaserde(rename = "oIDReference", prefix = "xcep")]
  o_id_references: Vec<i32>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct KeyArchivalAttributes
{
  #[yaserde(rename = "symmetricAlgorithmOIDReference", prefix = "xcep")]
  symmetric_algorithm_oid_reference: i32,

  #[yaserde(rename = "symmetricAlgorithmKeyLength", prefix = "xcep")]
  symmetric_algorithm_key_length: u32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct ExtensionsType
{
  #[yaserde(rename = "extension", prefix = "xcep")]
  extensions: Vec<Extension>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Extension
{
  #[yaserde(rename = "oIDReference", prefix = "xcep")]
  o_id_reference: i32,

  #[yaserde(rename = "critical", prefix = "xcep")]
  critical: bool,
  
  #[yaserde(rename = "value", prefix = "xcep")]
  value: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateAuthorities
{
  #[yaserde(rename = "cA", prefix = "xcep")]
  cas: Vec<CertificateAuthority>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateAuthority
{
  #[yaserde(rename = "uris", prefix = "xcep")]
  endpoints: Option<CertificateAuthorityEndpoints>,

  #[yaserde(rename = "certificate", prefix = "xcep")]
  certificate: String,

  #[yaserde(rename = "enrollPermission", prefix = "xcep")]
  enroll_permission: bool,

  #[yaserde(rename = "cAReferenceID", prefix = "xcep")]
  reference_id: i32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CertificateAuthorityEndpoints
{
  #[yaserde(rename = "cAURI", prefix = "xcep")]
  endpoints: Vec<CertificateAuthorityEndpoint>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateAuthorityEndpoint
{
  #[yaserde(rename = "clientAuthentication", prefix = "xcep")]
  client_authentication: u32,

  #[yaserde(rename = "uri", prefix = "xcep")]
  uri: String,
  
  #[yaserde(rename = "priority", prefix = "xcep")]
  priority: u32,

  #[yaserde(rename = "renewalOnly", prefix = "xcep")]
  renewal_only: bool
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct OiDsType
{
  #[yaserde(rename = "oID", prefix = "xcep")]
  o_ids: Vec<Oid>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Oid
{
  #[yaserde(rename = "value", prefix = "xcep")]
  value: Option<String>,
  
  #[yaserde(rename = "group", prefix = "xcep")]
  group: u32,
  
  #[yaserde(rename = "oIDReferenceID", prefix = "xcep")]
  o_id_reference_id: i32,

  #[yaserde(rename = "defaultName", prefix = "xcep")]
  default_name: String
}