mod soap_core
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        FaultcodeEnum
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        EnvelopeType
        {
            #[yaserde(rename = "Header", prefix = "soap")] pub header : crate
            :: schemas :: wsa :: types :: HeaderType,
            #[yaserde(rename = "Body", prefix = "soap")] pub body : BodyType,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct BodyType
        {
            #[yaserde(rename = "Fault", prefix = "soap")] pub fault : Option <
            FaultType >, #[yaserde(rename = "NotUnderstood", prefix = "soap")]
            pub not_understood : Option < NotUnderstoodType >,
            #[yaserde(rename = "Upgrade", prefix = "soap")] pub upgrade :
            Option < UpgradeType >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct FaultType
        {
            #[yaserde(rename = "Code", prefix = "soap")] pub code : Faultcode,
            #[yaserde(rename = "Reason", prefix = "soap")] pub reason :
            Faultreason, #[yaserde(rename = "Node", prefix = "soap")] pub node
            : Option < String >, #[yaserde(rename = "Role", prefix = "soap")]
            pub role : Option < String >,
            #[yaserde(rename = "Detail", prefix = "soap")] pub detail : Option
            < Detail >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        Faultreason
        {
            #[yaserde(rename = "Text", prefix = "soap")] pub texts : Vec <
            Reasontext >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        Reasontext { #[yaserde(text)] pub content : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct Faultcode
        {
            #[yaserde(rename = "Value", prefix = "soap")] pub value :
            FaultcodeEnum, #[yaserde(rename = "Subcode", prefix = "soap")] pub
            subcode : Option < Subcode >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct Subcode
        { #[yaserde(rename = "Value", prefix = "soap")] pub value : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct Detail {}
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        NotUnderstoodType { #[yaserde(attribute)] pub qname : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        SupportedEnvType { #[yaserde(attribute)] pub qname : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        UpgradeType
        {
            #[yaserde(rename = "SupportedEnvelope", prefix = "soap")] pub
            supported_envelopes : Vec < SupportedEnvType >,
        }
    }
    #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
    YaDeserialize, yaserde_derive :: YaSerialize)]
    #[yaserde(prefix = "soap", namespace =
    "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct Envelope
    { #[yaserde(flatten)] pub content : types :: EnvelopeType, }
} pub use soap_core :: * ;mod soap_xcep
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "soap", namespace =
        "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct
        EnvelopeType
        {
            #[yaserde(rename = "Header", prefix = "soap")] pub header : crate
            :: schemas :: wsa :: types :: HeaderType,
            #[yaserde(rename = "Body", prefix = "soap")] pub body : crate ::
            schemas :: xcep :: types :: BodyType,
        }
    }
    #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
    YaDeserialize, yaserde_derive :: YaSerialize)]
    #[yaserde(prefix = "soap", namespace =
    "soap: http://www.w3.org/2003/05/soap-envelope")] pub struct Envelope
    { #[yaserde(flatten)] pub content : types :: EnvelopeType, }
} pub use soap_xcep :: * ;mod wsa
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        RelationshipTypeOpenEnum
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        RelationshipType
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        FaultCodesOpenEnumType
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        FaultCodesType
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct HeaderType
        {
            #[yaserde(rename = "ReplyTo", prefix = "wsa")] pub reply_to :
            Option < crate :: schemas :: wsa :: types :: EndpointReferenceType
            >, #[yaserde(rename = "From", prefix = "wsa")] pub from : Option <
            crate :: schemas :: wsa :: types :: EndpointReferenceType >,
            #[yaserde(rename = "FaultTo", prefix = "wsa")] pub fault_to :
            Option < crate :: schemas :: wsa :: types :: EndpointReferenceType
            >, #[yaserde(rename = "EndpointReference", prefix = "wsa")] pub
            endpoint_reference : Option < crate :: schemas :: wsa :: types ::
            EndpointReferenceType >, #[yaserde(rename = "To", prefix = "wsa")]
            pub to : Option < crate :: schemas :: wsa :: types ::
            AttributedUriType >, #[yaserde(rename = "Action", prefix = "wsa")]
            pub action : Option < crate :: schemas :: wsa :: types ::
            AttributedUriType >,
            #[yaserde(rename = "ProblemIRI", prefix = "wsa")] pub problem_iri
            : Option < crate :: schemas :: wsa :: types :: AttributedUriType
            >, #[yaserde(rename = "MessageID", prefix = "wsa")] pub message_id
            : Option < crate :: schemas :: wsa :: types :: AttributedUriType
            >, #[yaserde(rename = "RetryAfter", prefix = "wsa")] pub
            retry_after : Option < crate :: schemas :: wsa :: types ::
            AttributedUnsignedLongType >,
            #[yaserde(rename = "ReferenceParameters", prefix = "wsa")] pub
            reference_parameters : Option < crate :: schemas :: wsa :: types
            :: ReferenceParametersType >,
            #[yaserde(rename = "Metadata", prefix = "wsa")] pub metadata :
            Option < crate :: schemas :: wsa :: types :: MetadataType >,
            #[yaserde(rename = "RelatesTo", prefix = "wsa")] pub relates_to :
            Option < crate :: schemas :: wsa :: types :: RelatesToType >,
            #[yaserde(rename = "ProblemHeaderstring", prefix = "wsa")] pub
            problem_headerstring : Option < crate :: schemas :: wsa :: types
            :: AttributedstringType >,
            #[yaserde(rename = "ProblemAction", prefix = "wsa")] pub
            problem_action : Option < crate :: schemas :: wsa :: types ::
            ProblemActionType >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        EndpointReferenceType
        {
            #[yaserde(rename = "Address", prefix = "wsa")] pub address : crate
            :: schemas :: wsa :: types :: AttributedUriType,
            #[yaserde(rename = "ReferenceParameters", prefix = "wsa")] pub
            reference_parameters : Option < crate :: schemas :: wsa :: types
            :: ReferenceParametersType >,
            #[yaserde(rename = "Metadata", prefix = "wsa")] pub metadata :
            Option < crate :: schemas :: wsa :: types :: MetadataType >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        ReferenceParametersType {}
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct MetadataType
        {}
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct RelatesToType
        {
            #[yaserde(text)] pub content : String,
            #[yaserde(attribute, rename = "RelationshipType")] pub
            relationship_type : Option < crate :: schemas :: wsa :: types ::
            RelationshipTypeOpenEnum >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        AttributedUriType { #[yaserde(text)] pub content : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        AttributedUnsignedLongType { pub content : u64, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        AttributedstringType { #[yaserde(text)] pub content : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsa", namespace =
        "wsa: http://www.w3.org/2005/08/addressing")] pub struct
        ProblemActionType
        {
            #[yaserde(rename = "Action", prefix = "wsa")] pub action : Option
            < crate :: schemas :: wsa :: types :: AttributedUriType >,
            #[yaserde(rename = "SoapAction", prefix = "wsa")] pub soap_action
            : Option < String >,
        }
    }
} pub use wsa :: * ;mod ws_security_extensions
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsse", namespace =
        "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
        pub struct BinarySecurityTokenType
        {
            pub content : crate :: schemas :: ws_security_extensions :: types
            :: EncodedString, #[yaserde(attribute, rename = "ValueType")] pub
            value_type : Option < String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsse", namespace =
        "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
        pub struct EncodedString
        {
            pub content : crate :: schemas :: ws_security_extensions :: types
            :: AttributedString,
            #[yaserde(attribute, rename = "EncodingType")] pub encoding_type :
            Option < String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wsse", namespace =
        "wsse: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
        pub struct AttributedString { #[yaserde(text)] pub content : String, }
    }
} pub use ws_security_extensions :: * ;mod ws_trust
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        TokenTypeEnum
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        RequestTypeEnum
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        BodyType
        {
            #[yaserde(rename = "RequestSecurityToken", prefix = "wst")] pub
            request_security_token : Option < crate :: schemas :: ws_trust ::
            types :: RequestSecurityTokenType >,
            #[yaserde(rename = "RequestSecurityTokenResponseCollection",
            prefix = "wst")] pub request_security_token_response_collection :
            Option < crate :: schemas :: ws_trust :: types ::
            RequestSecurityTokenResponseCollectionType >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        RequestSecurityTokenType
        {
            #[yaserde(rename = "TokenType", prefix = "wst")] pub token_type :
            crate :: schemas :: ws_trust :: types :: TokenTypeEnum,
            #[yaserde(rename = "RequestType", prefix = "wst")] pub
            request_type : crate :: schemas :: ws_trust :: types ::
            RequestTypeEnum,
            #[yaserde(rename = "BinarySecurityToken", prefix = "wst")] pub
            binary_security_token : crate :: schemas :: ws_security_extensions
            :: types :: BinarySecurityTokenType,
            #[yaserde(rename = "RequestID", prefix = "wst")] pub request_id :
            crate :: schemas :: ws_tep :: types :: RequestIdType,
            #[yaserde(attribute, rename = "Context")] pub context : Option <
            String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        RequestSecurityTokenResponseType
        {
            #[yaserde(rename = "TokenType", prefix = "wst")] pub token_type :
            crate :: schemas :: ws_trust :: types :: TokenTypeEnum,
            #[yaserde(rename = "DispositionMessage", prefix = "wst")] pub
            disposition_message : crate :: schemas :: ws_tep :: types ::
            DispositionMessageType,
            #[yaserde(rename = "BinarySecurityToken", prefix = "wst")] pub
            binary_security_token : crate :: schemas :: ws_security_extensions
            :: types :: BinarySecurityTokenType,
            #[yaserde(rename = "RequestedSecurityToken", prefix = "wst")] pub
            requested_security_token : crate :: schemas :: ws_trust :: types
            :: RequestedSecurityTokenType,
            #[yaserde(rename = "RequestID", prefix = "wst")] pub request_id :
            crate :: schemas :: ws_tep :: types :: RequestIdType,
            #[yaserde(attribute, rename = "Context")] pub context : Option <
            String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        RequestedSecurityTokenType {}
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wst", namespace =
        "wst: http://docs.oasis-open.org/ws-sx/ws-trust/200512/")] pub struct
        RequestSecurityTokenResponseCollectionType
        {
            #[yaserde(rename = "RequestSecurityTokenResponse", prefix =
            "wst")] pub request_security_token_responses : Vec < crate ::
            schemas :: ws_trust :: types :: RequestSecurityTokenResponseType
            >,
        }
    }
} pub use ws_trust :: * ;mod ws_tep
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wstep", namespace =
        "wstep: http://schemas.microsoft.com/windows/pki/2009/01/enrollment")]
        pub struct RequestIdType
        { #[yaserde(text)] pub content : std :: string :: String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wstep", namespace =
        "wstep: http://schemas.microsoft.com/windows/pki/2009/01/enrollment")]
        pub struct DispositionMessageType
        { #[yaserde(text)] pub content : String, }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "wstep", namespace =
        "wstep: http://schemas.microsoft.com/windows/pki/2009/01/enrollment")]
        pub struct CertificateEnrollmentWsDetailType
        {
            #[yaserde(rename = "BinaryResponse", prefix = "wstep")] pub
            binary_response : Option < String >,
            #[yaserde(rename = "ErrorCode", prefix = "wstep")] pub error_code
            : Option < i32 >,
            #[yaserde(rename = "InvalidRequest", prefix = "wstep")] pub
            invalid_request : Option < bool >,
            #[yaserde(rename = "RequestID", prefix = "wstep")] pub request_id
            : Option < String >,
        }
    }
} pub use ws_tep :: * ;mod xcep
{
    pub mod types
    {
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct BodyType
        {
            #[yaserde(rename = "GetPolicies", prefix = "xcep")] pub
            get_policies : Option < crate :: schemas :: xcep :: types ::
            GetPoliciesType >,
            #[yaserde(rename = "GetPoliciesResponse", prefix = "xcep")] pub
            get_policies_response : Option < crate :: schemas :: xcep :: types
            :: GetPoliciesResponseType >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Client
        {
            #[yaserde(rename = "lastUpdate", prefix = "xcep")] pub last_update
            : String,
            #[yaserde(rename = "preferredLanguage", prefix = "xcep")] pub
            preferred_language : String,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct GetPoliciesType
        {
            #[yaserde(rename = "client", prefix = "xcep")] pub client : crate
            :: schemas :: xcep :: types :: Client,
            #[yaserde(rename = "requestFilter", prefix = "xcep")] pub
            request_filter : crate :: schemas :: xcep :: types ::
            RequestFilter,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct RequestFilter
        {
            #[yaserde(rename = "policyOIDs", prefix = "xcep")] pub
            policy_oi_ds : crate :: schemas :: xcep :: types ::
            PolicyOiDsType,
            #[yaserde(rename = "clientVersion", prefix = "xcep")] pub
            client_version : i32,
            #[yaserde(rename = "serverVersion", prefix = "xcep")] pub
            server_version : i32,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct PolicyOiDsType
        {
            #[yaserde(rename = "oid", prefix = "xcep")] pub oids : Vec <
            String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct GetPoliciesResponseType
        {
            #[yaserde(rename = "response", prefix = "xcep")] pub response :
            crate :: schemas :: xcep :: types :: Response,
            #[yaserde(rename = "cAs", prefix = "xcep")] pub c_as : crate ::
            schemas :: xcep :: types :: CAsType,
            #[yaserde(rename = "oIDs", prefix = "xcep")] pub o_i_ds : crate ::
            schemas :: xcep :: types :: OiDsType,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Response
        {
            #[yaserde(rename = "policyID", prefix = "xcep")] pub policy_id :
            Option < String >,
            #[yaserde(rename = "policyFriendlyName", prefix = "xcep")] pub
            policy_friendly_name : String,
            #[yaserde(rename = "nextUpdateHours", prefix = "xcep")] pub
            next_update_hours : u32,
            #[yaserde(rename = "policiesNotChanged", prefix = "xcep")] pub
            policies_not_changed : bool,
            #[yaserde(rename = "policies", prefix = "xcep")] pub policies :
            crate :: schemas :: xcep :: types ::
            CertificateEnrollmentPoliciesType,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CertificateEnrollmentPoliciesType
        {
            #[yaserde(rename = "policy", prefix = "xcep")] pub policys : Vec <
            crate :: schemas :: xcep :: types :: CertificateEnrollmentPolicy
            >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CertificateEnrollmentPolicy
        {
            #[yaserde(rename = "policyOIDReference", prefix = "xcep")] pub
            policy_oid_reference : i32,
            #[yaserde(rename = "cAs", prefix = "xcep")] pub c_as : crate ::
            schemas :: xcep :: types :: CaReferencesType,
            #[yaserde(rename = "attributes", prefix = "xcep")] pub attributes
            : Option < crate :: schemas :: xcep :: types :: Attributes >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CaReferencesType
        {
            #[yaserde(rename = "cAReference", prefix = "xcep")] pub
            c_a_references : Vec < i32 >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Attributes
        {
            #[yaserde(rename = "commonName", prefix = "xcep")] pub common_name
            : Option < String >,
            #[yaserde(rename = "policySchema", prefix = "xcep")] pub
            policy_schema : u32,
            #[yaserde(rename = "certificateValidity", prefix = "xcep")] pub
            certificate_validity : Option < crate :: schemas :: xcep :: types
            :: CertificateValidity >,
            #[yaserde(rename = "permission", prefix = "xcep")] pub permission
            : Option < crate :: schemas :: xcep :: types ::
            EnrollmentPermission >,
            #[yaserde(rename = "privateKeyAttributes", prefix = "xcep")] pub
            private_key_attributes : Option < crate :: schemas :: xcep ::
            types :: PrivateKeyAttributes >,
            #[yaserde(rename = "revision", prefix = "xcep")] pub revision :
            Option < crate :: schemas :: xcep :: types :: Revision >,
            #[yaserde(rename = "supersededPolicies", prefix = "xcep")] pub
            superseded_policies : crate :: schemas :: xcep :: types ::
            CommonNamesType,
            #[yaserde(rename = "privateKeyFlags", prefix = "xcep")] pub
            private_key_flags : u32,
            #[yaserde(rename = "subjectNameFlags", prefix = "xcep")] pub
            subject_name_flags : u32,
            #[yaserde(rename = "enrollmentFlags", prefix = "xcep")] pub
            enrollment_flags : u32,
            #[yaserde(rename = "generalFlags", prefix = "xcep")] pub
            general_flags : u32,
            #[yaserde(rename = "hashAlgorithmOIDReference", prefix = "xcep")]
            pub hash_algorithm_oid_reference : i32,
            #[yaserde(rename = "rARequirements", prefix = "xcep")] pub
            r_a_requirements : crate :: schemas :: xcep :: types ::
            RaRequirements,
            #[yaserde(rename = "keyArchivalAttributes", prefix = "xcep")] pub
            key_archival_attributes : crate :: schemas :: xcep :: types ::
            KeyArchivalAttributes,
            #[yaserde(rename = "extensions", prefix = "xcep")] pub extensions
            : crate :: schemas :: xcep :: types :: ExtensionsType,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CertificateValidity
        {
            #[yaserde(rename = "validityPeriodSeconds", prefix = "xcep")] pub
            validity_period_seconds : u64,
            #[yaserde(rename = "renewalPeriodSeconds", prefix = "xcep")] pub
            renewal_period_seconds : u64,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct EnrollmentPermission
        {
            #[yaserde(rename = "enroll", prefix = "xcep")] pub enroll : bool,
            #[yaserde(rename = "autoEnroll", prefix = "xcep")] pub auto_enroll
            : bool,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct PrivateKeyAttributes
        {
            #[yaserde(rename = "minimalKeyLength", prefix = "xcep")] pub
            minimal_key_length : u32,
            #[yaserde(rename = "keySpec", prefix = "xcep")] pub key_spec :
            u32, #[yaserde(rename = "keyUsageProperty", prefix = "xcep")] pub
            key_usage_property : u32,
            #[yaserde(rename = "permissions", prefix = "xcep")] pub
            permissions : String,
            #[yaserde(rename = "algorithmOIDReference", prefix = "xcep")] pub
            algorithm_oid_reference : i32,
            #[yaserde(rename = "cryptoProviders", prefix = "xcep")] pub
            crypto_providers : crate :: schemas :: xcep :: types ::
            ProvidersType,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct ProvidersType
        {
            #[yaserde(rename = "provider", prefix = "xcep")] pub providers :
            Vec < String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Revision
        {
            #[yaserde(rename = "majorRevision", prefix = "xcep")] pub
            major_revision : u32,
            #[yaserde(rename = "minorRevision", prefix = "xcep")] pub
            minor_revision : u32,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CommonNamesType
        {
            #[yaserde(rename = "commonName", prefix = "xcep")] pub
            common_names : Vec < String >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct RaRequirements
        {
            #[yaserde(rename = "rASignatures", prefix = "xcep")] pub
            r_a_signatures : u32,
            #[yaserde(rename = "rAEKUs", prefix = "xcep")] pub r_aek_us :
            crate :: schemas :: xcep :: types :: OidReferencesType,
            #[yaserde(rename = "rAPolicies", prefix = "xcep")] pub
            r_a_policies : crate :: schemas :: xcep :: types ::
            OidReferencesType,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct OidReferencesType
        {
            #[yaserde(rename = "oIDReference", prefix = "xcep")] pub
            o_id_references : Vec < i32 >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct KeyArchivalAttributes
        {
            #[yaserde(rename = "symmetricAlgorithmOIDReference", prefix =
            "xcep")] pub symmetric_algorithm_oid_reference : i32,
            #[yaserde(rename = "symmetricAlgorithmKeyLength", prefix =
            "xcep")] pub symmetric_algorithm_key_length : u32,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct ExtensionsType
        {
            #[yaserde(rename = "extension", prefix = "xcep")] pub extensions :
            Vec < crate :: schemas :: xcep :: types :: Extension >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Extension
        {
            #[yaserde(rename = "oIDReference", prefix = "xcep")] pub
            o_id_reference : i32,
            #[yaserde(rename = "critical", prefix = "xcep")] pub critical :
            bool, #[yaserde(rename = "value", prefix = "xcep")] pub value :
            String,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CAsType
        {
            #[yaserde(rename = "cA", prefix = "xcep")] pub c_as : Vec < crate
            :: schemas :: xcep :: types :: Ca >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Ca
        {
            #[yaserde(rename = "uris", prefix = "xcep")] pub uris : Option <
            crate :: schemas :: xcep :: types :: CaurIsType >,
            #[yaserde(rename = "certificate", prefix = "xcep")] pub
            certificate : Option < String >,
            #[yaserde(rename = "enrollPermission", prefix = "xcep")] pub
            enroll_permission : bool,
            #[yaserde(rename = "cAReferenceID", prefix = "xcep")] pub
            c_a_reference_id : i32,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct CaurIsType
        {
            #[yaserde(rename = "cAURI", prefix = "xcep")] pub c_auris : Vec <
            crate :: schemas :: xcep :: types :: Cauri >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Cauri
        {
            #[yaserde(rename = "clientAuthentication", prefix = "xcep")] pub
            client_authentication : u32,
            #[yaserde(rename = "uri", prefix = "xcep")] pub uri : Option <
            String >, #[yaserde(rename = "priority", prefix = "xcep")] pub
            priority : u32,
            #[yaserde(rename = "renewalOnly", prefix = "xcep")] pub
            renewal_only : bool,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct OiDsType
        {
            #[yaserde(rename = "oID", prefix = "xcep")] pub o_ids : Vec <
            crate :: schemas :: xcep :: types :: Oid >,
        }
        #[derive(Clone, Debug, Default, PartialEq, yaserde_derive ::
        YaDeserialize, yaserde_derive :: YaSerialize)]
        #[yaserde(prefix = "xcep", namespace =
        "xcep: http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy")]
        pub struct Oid
        {
            #[yaserde(rename = "value", prefix = "xcep")] pub value : Option <
            String >, #[yaserde(rename = "group", prefix = "xcep")] pub group
            : u32, #[yaserde(rename = "oIDReferenceID", prefix = "xcep")] pub
            o_id_reference_id : i32,
            #[yaserde(rename = "defaultName", prefix = "xcep")] pub
            default_name : String,
        }
    }
} pub use xcep :: * ;