use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Client
{
  #[yaserde(rename = "lastUpdate", prefix = "xcep")]
  last_update: String,

  #[yaserde(rename = "preferredLanguage", prefix = "xcep")]
  preferred_language: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct GetPoliciesType
{
  #[yaserde(rename = "client", prefix = "xcep")]
  client: Client,

  #[yaserde(rename = "requestFilter", prefix = "xcep")]
  request_filter: RequestFilter
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
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct GetPoliciesResponseType
{
  #[yaserde(rename = "response", prefix = "xcep")]
  response: Response,

  #[yaserde(rename = "cAs", prefix = "xcep")]
  c_as: CAsType,

  #[yaserde(rename = "oIDs", prefix = "xcep")]
  o_i_ds: OiDsType
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
  policies: CertificateEnrollmentPoliciesType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateEnrollmentPoliciesType
{
  #[yaserde(rename = "policy", prefix = "xcep")]
  policys: Vec<CertificateEnrollmentPolicy>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CertificateEnrollmentPolicy
{
  #[yaserde(rename = "policyOIDReference", prefix = "xcep")]
  policy_oid_reference: i32,

  #[yaserde(rename = "cAs", prefix = "xcep")]
  c_as: CaReferencesType,

  #[yaserde(rename = "attributes", prefix = "xcep")]
  attributes: Option<Attributes>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CaReferencesType
{
  #[yaserde(rename = "cAReference", prefix = "xcep")]
  c_a_references : Vec <i32>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace ="xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Attributes
{
  #[yaserde(rename = "commonName", prefix = "xcep")]
  common_name: Option<String>,

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
struct CAsType
{
  #[yaserde(rename = "cA", prefix = "xcep")]
  c_as: Vec<Ca>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Ca
{
  #[yaserde(rename = "uris", prefix = "xcep")]
  uris: Option<CaurIsType>,

  #[yaserde(rename = "certificate", prefix = "xcep")]
  certificate: Option<String>,

  #[yaserde(rename = "enrollPermission", prefix = "xcep")]
  enroll_permission: bool,

  #[yaserde(rename = "cAReferenceID", prefix = "xcep")]
  c_a_reference_id: i32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct CaurIsType
{
  #[yaserde(rename = "cAURI", prefix = "xcep")]
  c_auris: Vec<Cauri>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
struct Cauri
{
  #[yaserde(rename = "clientAuthentication", prefix = "xcep")]
  client_authentication: u32,

  #[yaserde(rename = "uri", prefix = "xcep")]
  uri: Option<String>,
  
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