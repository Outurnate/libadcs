use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct EnvelopeType
{
    #[yaserde(rename = "Header", prefix = "soap")]
    pub header: HeaderType,

    #[yaserde(rename = "Body", prefix = "soap")]
    pub body: BodyType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub enum BodyType
{
    #[yaserde(rename = "Fault", prefix = "soap")]
    Fault(FaultType),

    #[yaserde(rename = "NotUnderstood", prefix = "soap")]
    NotUnderstood(NotUnderstoodType),

    #[yaserde(rename = "Upgrade", prefix = "soap")]
    Upgrade(UpgradeType),

    #[yaserde(rename = "RequestSecurityToken", prefix = "wst")]
    RequestSecurityToken(RequestSecurityTokenType),

    #[yaserde(rename = "RequestSecurityTokenResponseCollection", prefix = "wst")]
    RequestSecurityTokenResponseCollection(RequestSecurityTokenResponseCollectionType),

    #[yaserde(rename = "GetPolicies", prefix = "xcep")]
    GetPolicies(GetPoliciesType),

    #[yaserde(rename = "GetPoliciesResponse", prefix = "xcep")]
    GetPoliciesResponse(GetPoliciesResponseType),

    #[default]
    None
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct FaultType
{
    #[yaserde(rename = "Code", prefix = "soap")]
    pub code: Faultcode,

    #[yaserde(rename = "Reason", prefix = "soap")]
    pub reason: Faultreason,
    
    #[yaserde(rename = "Node", prefix = "soap")]
    pub node: Option<String>,
    
    #[yaserde(rename = "Role", prefix = "soap")]
    pub role: Option<String>,

    #[yaserde(rename = "Detail", prefix = "soap")]
    pub detail: Option<Detail>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Faultreason
{
    #[yaserde(rename = "Text", prefix = "soap")]
    pub texts: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Faultcode
{
    #[yaserde(rename = "Value", prefix = "soap")]
    pub value: String,
    
    #[yaserde(rename = "Subcode", prefix = "soap")]
    pub subcode: Option<Subcode>,
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Subcode
{
    #[yaserde(rename = "Value", prefix = "soap")]
    pub value: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Detail
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct NotUnderstoodType
{
    #[yaserde(attribute)]
    pub qname: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct SupportedEnvType
{
    #[yaserde(attribute)]
    pub qname: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct UpgradeType
{
    #[yaserde(rename = "SupportedEnvelope", prefix = "soap")]
    pub supported_envelopes: Vec<SupportedEnvType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "soap", namespace = "soap: http://www.w3.org/2003/05/soap-envelope")]
pub struct Envelope
{
    #[yaserde(flatten)]
    pub content: EnvelopeType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct HeaderType
{
    #[yaserde(rename = "ReplyTo", prefix = "wsa")]
    pub reply_to: Option<EndpointReferenceType>,
    
    #[yaserde(rename = "From", prefix = "wsa")]
    pub from: Option<EndpointReferenceType>,
    
    #[yaserde(rename = "FaultTo", prefix = "wsa")]
    pub fault_to: Option<EndpointReferenceType>,
    
    #[yaserde(rename = "EndpointReference", prefix = "wsa")]
    pub endpoint_reference: Option<EndpointReferenceType>,
    
    #[yaserde(rename = "To", prefix = "wsa")]
    pub to: Option<String>,
    
    #[yaserde(rename = "Action", prefix = "wsa")]
    pub action: Option<String>,
    
    #[yaserde(rename = "ProblemIRI", prefix = "wsa")]
    pub problem_iri: Option<String>,
    
    #[yaserde(rename = "MessageID", prefix = "wsa")]
    pub message_id: Option<String>,
    
    #[yaserde(rename = "RetryAfter", prefix = "wsa")]
    pub retry_after: Option<u64>,
    
    #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
    pub reference_parameters: Option<ReferenceParametersType>,
    
    #[yaserde(rename = "Metadata", prefix = "wsa")]
    pub metadata: Option<MetadataType>,
    
    #[yaserde(rename = "RelatesTo", prefix = "wsa")]
    pub relates_to: Option<RelatesToType>,
    
    #[yaserde(rename = "ProblemHeaderstring", prefix = "wsa")]
    pub problem_headerstring: Option<String>,
    
    #[yaserde(rename = "ProblemAction", prefix = "wsa")]
    pub problem_action: Option<ProblemActionType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct EndpointReferenceType
{
    #[yaserde(rename = "Address", prefix = "wsa")]
    pub address: String,

    #[yaserde(rename = "ReferenceParameters", prefix = "wsa")]
    pub reference_parameters: Option<ReferenceParametersType>,

    #[yaserde(rename = "Metadata", prefix = "wsa")]
    pub metadata: Option<MetadataType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct ReferenceParametersType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct MetadataType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct RelatesToType
{
    #[yaserde(text)] pub content : String,

    #[yaserde(attribute, rename = "String")]
    pub relationship_type : Option <String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsa", namespace = "wsa: http://www.w3.org/2005/08/addressing")]
pub struct ProblemActionType
{
    #[yaserde(rename = "Action", prefix = "wsa")]
    pub action: Option<String>,

    #[yaserde(rename = "SoapAction", prefix = "wsa")]
    pub soap_action: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsse", namespace = "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
pub struct BinarySecurityTokenType
{
    pub content: EncodedString,
    
    #[yaserde(attribute, rename = "ValueType")]
    pub value_type: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wsse", namespace = "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
pub struct EncodedString
{
    pub content: String,

    #[yaserde(attribute, rename = "EncodingType")]
    pub encoding_type: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
pub struct RequestSecurityTokenType
{
    #[yaserde(rename = "TokenType", prefix = "wst")]
    pub token_type: String,

    #[yaserde(rename = "RequestType", prefix = "wst")]
    pub request_type: String,

    #[yaserde(rename = "BinarySecurityToken", prefix = "wst")]
    pub binary_security_token: BinarySecurityTokenType,

    #[yaserde(rename = "RequestID", prefix = "wst")]
    pub request_id: String,

    #[yaserde(attribute, rename = "Context")]
    pub context: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
pub struct RequestSecurityTokenResponseType
{
    #[yaserde(rename = "TokenType", prefix = "wst")]
    pub token_type: String,

    #[yaserde(rename = "DispositionMessage", prefix = "wst")]
    pub disposition_message: String,

    #[yaserde(rename = "BinarySecurityToken", prefix = "wst")]
    pub binary_security_token: BinarySecurityTokenType,

    #[yaserde(rename = "RequestedSecurityToken", prefix = "wst")]
    pub requested_security_token: RequestedSecurityTokenType,

    #[yaserde(rename = "RequestID", prefix = "wst")]
    pub request_id: String,

    #[yaserde(attribute, rename = "Context")]
    pub context: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
pub struct RequestedSecurityTokenType
{
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wst", namespace = "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")]
pub struct RequestSecurityTokenResponseCollectionType
{
    #[yaserde(rename = "RequestSecurityTokenResponse", prefix = "wst")]
    pub request_security_token_responses: Vec<RequestSecurityTokenResponseType>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "wstep", namespace = "wstep: http://schemas.microsoft.com/windows/pki/2009/01/enrollment")]
pub struct CertificateEnrollmentWsDetailType
{
    #[yaserde(rename = "BinaryResponse", prefix = "wstep")]
    pub binary_response: Option<String>,

    #[yaserde(rename = "ErrorCode", prefix = "wstep")]
    pub error_code: Option<i32>,

    #[yaserde(rename = "InvalidRequest", prefix = "wstep")]
    pub invalid_request: Option<bool>,

    #[yaserde(rename = "RequestID", prefix = "wstep")]
    pub request_id: Option<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Client
{
    #[yaserde(rename = "lastUpdate", prefix = "xcep")]
    pub last_update: String,

    #[yaserde(rename = "preferredLanguage", prefix = "xcep")]
    pub preferred_language: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct GetPoliciesType
{
    #[yaserde(rename = "client", prefix = "xcep")]
    pub client: Client,

    #[yaserde(rename = "requestFilter", prefix = "xcep")]
    pub request_filter: RequestFilter,
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct RequestFilter
{
    #[yaserde(rename = "policyOIDs", prefix = "xcep")]
    pub policy_oi_ds: PolicyOiDsType,

    #[yaserde(rename = "clientVersion", prefix = "xcep")]
    pub client_version: i32,

    #[yaserde(rename = "serverVersion", prefix = "xcep")]
    pub server_version: i32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct PolicyOiDsType
{
    #[yaserde(rename = "oid", prefix = "xcep")]
    pub oids: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct GetPoliciesResponseType
{
    #[yaserde(rename = "response", prefix = "xcep")]
    pub response: Response,

    #[yaserde(rename = "cAs", prefix = "xcep")]
    pub c_as: CAsType,

    #[yaserde(rename = "oIDs", prefix = "xcep")]
    pub o_i_ds: OiDsType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Response
{
    #[yaserde(rename = "policyID", prefix = "xcep")]
    pub policy_id: Option<String>,

    #[yaserde(rename = "policyFriendlyName", prefix = "xcep")]
    pub policy_friendly_name: String,

    #[yaserde(rename = "nextUpdateHours", prefix = "xcep")]
    pub next_update_hours: u32,

    #[yaserde(rename = "policiesNotChanged", prefix = "xcep")]
    pub policies_not_changed: bool,

    #[yaserde(rename = "policies", prefix = "xcep")]
    pub policies: CertificateEnrollmentPoliciesType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CertificateEnrollmentPoliciesType
{
    #[yaserde(rename = "policy", prefix = "xcep")]
    pub policys: Vec<CertificateEnrollmentPolicy>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CertificateEnrollmentPolicy
{
    #[yaserde(rename = "policyOIDReference", prefix = "xcep")]
    pub policy_oid_reference: i32,

    #[yaserde(rename = "cAs", prefix = "xcep")]
    pub c_as: CaReferencesType,

    #[yaserde(rename = "attributes", prefix = "xcep")]
    pub attributes: Option<Attributes>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CaReferencesType
{
    #[yaserde(rename = "cAReference", prefix = "xcep")]
    pub c_a_references : Vec < i32 >
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace ="xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Attributes
{
    #[yaserde(rename = "commonName", prefix = "xcep")]
    pub common_name: Option<String>,

    #[yaserde(rename = "policySchema", prefix = "xcep")]
    pub policy_schema: u32,

    #[yaserde(rename = "certificateValidity", prefix = "xcep")]
    pub certificate_validity: Option<CertificateValidity>,

    #[yaserde(rename = "permission", prefix = "xcep")]
    pub permission: Option<EnrollmentPermission>,

    #[yaserde(rename = "privateKeyAttributes", prefix = "xcep")]
    pub private_key_attributes: Option<PrivateKeyAttributes>,

    #[yaserde(rename = "revision", prefix = "xcep")]
    pub revision: Option <Revision>,

    #[yaserde(rename = "supersededPolicies", prefix = "xcep")]
    pub superseded_policies: CommonNamesType,

    #[yaserde(rename = "privateKeyFlags", prefix = "xcep")]
    pub private_key_flags: u32,

    #[yaserde(rename = "subjectNameFlags", prefix = "xcep")]
    pub subject_name_flags: u32,

    #[yaserde(rename = "enrollmentFlags", prefix = "xcep")]
    pub enrollment_flags: u32,

    #[yaserde(rename = "generalFlags", prefix = "xcep")]
    pub general_flags: u32,

    #[yaserde(rename = "hashAlgorithmOIDReference", prefix = "xcep")]
    pub hash_algorithm_oid_reference: i32,

    #[yaserde(rename = "rARequirements", prefix = "xcep")]
    pub r_a_requirements: RaRequirements,

    #[yaserde(rename = "keyArchivalAttributes", prefix = "xcep")]
    pub key_archival_attributes: KeyArchivalAttributes,

    #[yaserde(rename = "extensions", prefix = "xcep")]
    pub extensions: ExtensionsType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CertificateValidity
{
    #[yaserde(rename = "validityPeriodSeconds", prefix = "xcep")]
    pub validity_period_seconds : u64,

    #[yaserde(rename = "renewalPeriodSeconds", prefix = "xcep")]
    pub renewal_period_seconds : u64
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct EnrollmentPermission
{
    #[yaserde(rename = "enroll", prefix = "xcep")]
    pub enroll: bool,

    #[yaserde(rename = "autoEnroll", prefix = "xcep")]
    pub auto_enroll: bool
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct PrivateKeyAttributes
{
    #[yaserde(rename = "minimalKeyLength", prefix = "xcep")]
    pub minimal_key_length: u32,

    #[yaserde(rename = "keySpec", prefix = "xcep")]
    pub key_spec: u32,
    
    #[yaserde(rename = "keyUsageProperty", prefix = "xcep")]
    pub key_usage_property: u32,

    #[yaserde(rename = "permissions", prefix = "xcep")]
    pub permissions: String,

    #[yaserde(rename = "algorithmOIDReference", prefix = "xcep")]
    pub algorithm_oid_reference: i32,

    #[yaserde(rename = "cryptoProviders", prefix = "xcep")]
    pub crypto_providers: ProvidersType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct ProvidersType
{
    #[yaserde(rename = "provider", prefix = "xcep")]
    pub providers: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Revision
{
    #[yaserde(rename = "majorRevision", prefix = "xcep")]
    pub major_revision: u32,

    #[yaserde(rename = "minorRevision", prefix = "xcep")]
    pub minor_revision: u32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CommonNamesType
{
    #[yaserde(rename = "commonName", prefix = "xcep")]
    pub common_names: Vec<String>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct RaRequirements
{
    #[yaserde(rename = "rASignatures", prefix = "xcep")]
    pub r_a_signatures: u32,

    #[yaserde(rename = "rAEKUs", prefix = "xcep")]
    pub r_aek_us: OidReferencesType,

    #[yaserde(rename = "rAPolicies", prefix = "xcep")]
    pub r_a_policies: OidReferencesType
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct OidReferencesType
{
    #[yaserde(rename = "oIDReference", prefix = "xcep")]
    pub o_id_references: Vec<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct KeyArchivalAttributes
{
    #[yaserde(rename = "symmetricAlgorithmOIDReference", prefix = "xcep")]
    pub symmetric_algorithm_oid_reference: i32,

    #[yaserde(rename = "symmetricAlgorithmKeyLength", prefix = "xcep")]
    pub symmetric_algorithm_key_length: u32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct ExtensionsType
{
    #[yaserde(rename = "extension", prefix = "xcep")]
    pub extensions: Vec<Extension>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Extension
{
    #[yaserde(rename = "oIDReference", prefix = "xcep")]
    pub o_id_reference: i32,

    #[yaserde(rename = "critical", prefix = "xcep")]
    pub critical: bool,
    
    #[yaserde(rename = "value", prefix = "xcep")]
    pub value: String
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CAsType
{
    #[yaserde(rename = "cA", prefix = "xcep")]
    pub c_as: Vec<Ca>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Ca
{
    #[yaserde(rename = "uris", prefix = "xcep")]
    pub uris: Option<CaurIsType>,

    #[yaserde(rename = "certificate", prefix = "xcep")]
    pub certificate: Option<String>,

    #[yaserde(rename = "enrollPermission", prefix = "xcep")]
    pub enroll_permission: bool,

    #[yaserde(rename = "cAReferenceID", prefix = "xcep")]
    pub c_a_reference_id: i32
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct CaurIsType
{
    #[yaserde(rename = "cAURI", prefix = "xcep")]
    pub c_auris: Vec<Cauri>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Cauri
{
    #[yaserde(rename = "clientAuthentication", prefix = "xcep")]
    pub client_authentication: u32,

    #[yaserde(rename = "uri", prefix = "xcep")]
    pub uri: Option<String>,
    
    #[yaserde(rename = "priority", prefix = "xcep")]
    pub priority: u32,

    #[yaserde(rename = "renewalOnly", prefix = "xcep")]
    pub renewal_only: bool
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct OiDsType
{
    #[yaserde(rename = "oID", prefix = "xcep")]
    pub o_ids: Vec<Oid>
}

#[derive(Clone, Debug, Default, PartialEq, YaDeserialize, YaSerialize)]
#[yaserde(prefix = "xcep", namespace = "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
pub struct Oid
{
    #[yaserde(rename = "value", prefix = "xcep")]
    pub value: Option<String>,
    
    #[yaserde(rename = "group", prefix = "xcep")]
    pub group: u32,
    
    #[yaserde(rename = "oIDReferenceID", prefix = "xcep")]
    pub o_id_reference_id: i32,

    #[yaserde(rename = "defaultName", prefix = "xcep")]
    pub default_name: String
}