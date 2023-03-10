mod sddl;

use ldap3::controls::RawControl;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::{LdapConn, Scope, SearchEntry, LdapError};
use sddl::{SDDL, AUTO_ENROLL, ENROLL};
use tracing::{instrument, event, Level};
use x509_certificate::certificate::X509Certificate;
use x509_certificate::X509CertificateError;

use crate::sddl::SID;

fn main() -> Result<(), LdapError>
{
  let subscriber = tracing_subscriber::FmtSubscriber::new();
  tracing::subscriber::set_global_default(subscriber).unwrap();

  let security_descriptor_flag_control = RawControl
  {
    ctype: "1.2.840.113556.1.4.801".to_owned(),
    crit: true,
    val: Some(vec![7])
  };
  let mut ldap = LdapConn::new("ldap://192.168.100.218:3268")?;
  let mut ldap = ldap.with_controls(vec![security_descriptor_flag_control]);
  ldap.simple_bind("CN=Administrator,CN=Users,DC=CONTOSO,DC=COM", "Password1")?.success()?;
  let rootdse = RootDSE::new(&mut ldap)?.unwrap();
  Ok(ldap.unbind()?)
}

#[derive(Debug)]
struct RootDSE
{
  configuration_naming_context: String,
  root_domain_naming_context: String,
  default_naming_context: String,
  certificate_templates: String,
  certification_authorities: String,
  enrollment_services: String
}

impl RootDSE
{
  fn new(ldap: &mut LdapConn) -> Result<Option<Self>, LdapError>
  {
    let (rs, _res) = ldap.search("", Scope::Base, "(objectClass=*)", vec!["configurationNamingContext", "rootDomainNamingContext", "defaultNamingContext"])?.success()?;
    if let Some(rootdse) = rs.into_iter().nth(0).map(|result| SearchEntry::construct(result))
    {
      match
      (
        rootdse.attrs.get("configurationNamingContext").and_then(|v| v.into_iter().nth(0)),
        rootdse.attrs.get("rootDomainNamingContext").and_then(|v| v.into_iter().nth(0)),
        rootdse.attrs.get("defaultNamingContext").and_then(|v| v.into_iter().nth(0))
      )
      {
        (
          Some(configuration_naming_context),
          Some(root_domain_naming_context),
          Some(default_naming_context)
        ) => Ok(Some(Self
        {
          configuration_naming_context: configuration_naming_context.to_string(),
          root_domain_naming_context: root_domain_naming_context.to_string(),
          default_naming_context: default_naming_context.to_string(),
          certificate_templates: format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,{}", configuration_naming_context),
          certification_authorities: format!("CN=Certification Authorities,CN=Public Key Services,CN=Services,{}", configuration_naming_context),
          enrollment_services: String::new()
        })),
        (_, _, _) => Ok(None)
      }
    }
    else { Ok(None) }
  }
}

struct LdapManager
{
  ldap: LdapConn,
  rootdse: RootDSE,
  me: LdapPrincipal,
}

impl LdapManager
{
  fn myself(ldap: &mut LdapConn, rootdse: &RootDSE) -> Result<Option<LdapPrincipal>, LdapError>
  {
    let (rs, _) = ldap.extended(WhoAmI)?.success()?;
    let rs = rs.parse::<WhoAmIResp>();
    let netbios_name = rs.authzid.split(":").into_iter().nth(1);
    let sam_account_name = netbios_name.and_then(|netbios_name| netbios_name.split("\\").nth(1));

    event!(Level::INFO, netbios_name = netbios_name, sam_account_name = sam_account_name);

    if let (Some(netbios_name), Some(sam_account_name)) = (netbios_name, sam_account_name)
    {
      Ok(LdapPrincipal::from_query(ldap, &rootdse.root_domain_naming_context, Scope::Subtree, &format!("(sAMAccountName={})", sam_account_name))?.into_iter()
        .filter(|user| user.principal_name == netbios_name)
        .nth(0))
    }
    else
    {
      Ok(None)
    }
  }

  fn is_member_of(ldap: &mut LdapConn, rootdse: &RootDSE, group: SID, member: SID) -> Result<bool, LdapError>
  {
    if let Some(group) = LdapPrincipal::from_query(ldap, &rootdse.root_domain_naming_context, Scope::Subtree, &group.to_ldap_predicate())?.into_iter().nth(0)
    {
      let filter = format!("(&(memberOf:1.2.840.113556.1.4.1941:={}){})", group.distinguished_name, member.to_ldap_predicate());
      Ok(LdapPrincipal::from_query(ldap, &rootdse.root_domain_naming_context, Scope::Subtree, &filter)?.len() > 0)
    }
    else
    {
      Ok(false)
    }
  }

  pub fn get_certificate_templates(&mut self) -> Result<Vec<LdapCertificateTemplate>, LdapError>
  {
    LdapCertificateTemplate::from_query(&mut self.ldap, &self.rootdse, Scope::OneLevel, "(objectClass=pKICertificateTemplate)")
  }

  pub fn get_root_certificates(&mut self) -> Result<Vec<X509Certificate>, LdapError>
  {
    let (rs, _) = self.ldap.search(&self.rootdse.certification_authorities, Scope::OneLevel, "(objectClass=certificationAuthority)", vec!["cACertificate"])?.success()?;
    Ok(rs.into_iter().filter_map(|result|
    {
      let result = SearchEntry::construct(result);
      result.bin_attrs.get("cACertificate").and_then(|v| v.into_iter().nth(0).and_then(|v| match X509Certificate::from_der(v)
      {
        Ok(certificate) => Some(certificate),
        Err(err) => { event!(Level::WARN, "{}", err); None }
      }))
    }).collect::<Vec<X509Certificate>>())
  }

  pub fn get_enrollment_service(&mut self) -> Result<Vec<LdapEnrollmentService>, LdapError>
  {
    LdapEnrollmentService::from_query(&mut self.ldap, &self.rootdse, scope, filter)
  }
}

struct LdapPrincipal
{
  object_sid: SID,
  principal_name: String,
  distinguished_name: String
}

impl LdapPrincipal
{
  fn from_query(ldap: &mut LdapConn, base: &str, scope: Scope, filter: &str) -> Result<Vec<Self>, LdapError>
  {
    let (rs, _) = ldap.search(base, scope, filter, vec!["objectSid", "msDS-PrincipalName", "distinguishedName"])?.success()?;
    Ok(rs.into_iter().filter_map(|rs|
    {
      let rs = SearchEntry::construct(rs);
      match
      (
        rs.bin_attrs.get("objectSid").and_then(|v|
          v.into_iter().nth(0).and_then(|bytes| match SID::new(bytes)
          {
            Ok(sid) => Some(sid),
            Err(err) => { event!(Level::WARN, "{}", err); None }
          })),
        rs.attrs.get("msDS-PrincipalName").and_then(|v| v.into_iter().nth(0).map(|v| v.to_owned())),
        rs.attrs.get("distinguishedName").and_then(|v| v.into_iter().nth(0).map(|v| v.to_owned())),
      )
      {
        (Some(object_sid), Some(principal_name), Some(distinguished_name)) => Some(Self { object_sid, principal_name, distinguished_name }),
        _ => None
      }
    }).collect::<Vec<Self>>())
  }
}

struct LdapCertificateTemplate
{
  cn: String,
  enroll: bool,
  auto_enroll: bool
}

impl LdapCertificateTemplate
{
  fn from_query(ldap: &mut LdapConn, rootdse: &RootDSE, scope: Scope, filter: &str) -> Result<Vec<Self>, LdapError>
  {
    let me = LdapManager::myself(ldap, rootdse)?.unwrap();
    let (rs, _) = ldap.search(&rootdse.certificate_templates, scope, filter, vec!["cn", "nTSecurityDescriptor"])?.success()?;
    Ok(rs.into_iter().filter_map(|rs|
    {
      let rs = SearchEntry::construct(rs);
      match
      (
        rs.attrs.get("cn").and_then(|v| v.into_iter().nth(0).map(|v| v.to_owned())),
        rs.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.into_iter().nth(0).and_then(|v|
          {
            let mut does_identify = |sid: &SID|
            {
              if me.object_sid == *sid
              {
                Ok(true)
              }
              else
              {
                LdapManager::is_member_of(ldap, rootdse, sid.clone(), me.object_sid.clone())
              }
            };
            match SDDL::new(v)
            {
              Ok(sddl) => Some((sddl.dacl.as_ref().unwrap().has_object_permission(&ENROLL, &mut does_identify).unwrap(), sddl.dacl.as_ref().unwrap().has_object_permission(&AUTO_ENROLL, &mut does_identify).unwrap())),
              Err(err) => { event!(Level::WARN, "{}", err); None }
            }
          }))
      )
      {
        (Some(cn), Some((enroll, auto_enroll))) => Some(Self { cn, enroll, auto_enroll }),
        _ => None
      }
    }).collect::<Vec<Self>>())
  }
}

struct LdapEnrollmentService
{
  cn: String,
  host_name: String,
  certificate: X509Certificate,
  templates: Vec<String>
}

impl LdapEnrollmentService
{
  fn from_query(ldap: &mut LdapConn, rootdse: &RootDSE, scope: Scope, filter: &str) -> Result<Vec<Self>, LdapError>
  {
    let me = LdapManager::myself(ldap, rootdse)?.unwrap();
    let (rs, _) = ldap.search(&rootdse.enrollment_services, scope, filter, vec!["cn", "dNSHostName", "cACertificate", "certificateTemplates"])?.success()?;
    Ok(rs.into_iter().filter_map(|rs|
    {
      let rs = SearchEntry::construct(rs);
      match
      (
        rs.attrs.get("cn").and_then(|v| v.into_iter().nth(0).map(|v| v.to_owned())),
        rs.attrs.get("dNSHostName").and_then(|v| v.into_iter().nth(0).map(|v| v.to_owned())),
        rs.bin_attrs.get("cACertificate").and_then(|v| v.into_iter().nth(0).and_then(|v| match X509Certificate::from_der(v)
        {
          Ok(certificate) => Some(certificate),
          Err(err) => { event!(Level::WARN, "{}", err); None }
        })),
        rs.attrs.get("certificateTemplates").map(|v| v.into_iter().cloned().collect())
      )
      {
        (Some(cn), Some(host_name), Some(certificate), Some(templates)) => Some(Self { cn, host_name, certificate, templates }),
        _ => None
      }
    }).collect::<Vec<Self>>())
  }
}