use std::collections::HashMap;
use std::fmt::Display;

use itertools::Itertools;
use ldap3::controls::RawControl;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::{Scope, SearchEntry, LdapError, LdapConn};
use log::{log, Level};
use tokio::runtime::Runtime;
use crate::NamedCertificate;
use crate::sddl::{SDDL, AUTO_ENROLL, ENROLL, SID};
use x509_certificate::certificate::X509Certificate;
use trust_dns_resolver::{AsyncResolver, name_server::{GenericConnection, GenericConnectionProvider}};
use rand::prelude::*;

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
    if let Some(rootdse) = rs.into_iter().next().map(|result| SearchEntry::construct(result))
    {
      match
      (
        rootdse.attrs.get("configurationNamingContext").and_then(|v| v.iter().next()),
        rootdse.attrs.get("rootDomainNamingContext").and_then(|v| v.iter().next()),
        rootdse.attrs.get("defaultNamingContext").and_then(|v| v.iter().next())
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

fn myself(ldap: &mut LdapConn, rootdse: &RootDSE) -> Result<Option<LdapPrincipal>, LdapError>
{
  let (rs, _) = ldap.extended(WhoAmI)?.success()?;
  let rs = rs.parse::<WhoAmIResp>();
  let netbios_name = rs.authzid.split(":").into_iter().nth(1);
  let sam_account_name = netbios_name.and_then(|netbios_name| netbios_name.split("\\").nth(1));

  //event!(Level::INFO, netbios_name = netbios_name, sam_account_name = sam_account_name);

  if let (Some(netbios_name), Some(sam_account_name)) = (netbios_name, sam_account_name)
  {
    Ok(LdapPrincipal::from_query(ldap, &rootdse.root_domain_naming_context, Scope::Subtree, &format!("(sAMAccountName={})", sam_account_name))?.into_iter()
      .find(|user| user.principal_name == netbios_name))
  }
  else
  {
    Ok(None)
  }
}

fn is_member_of(ldap: &mut LdapConn, rootdse: &RootDSE, group: SID, member: SID) -> Result<bool, LdapError>
{
  if let Some(group) = LdapPrincipal::from_query(ldap, &rootdse.root_domain_naming_context, Scope::Subtree, &group.to_ldap_predicate())?.first()
  {
    let filter = format!("(&(memberOf:1.2.840.113556.1.4.1941:={}){})", group.distinguished_name, member.to_ldap_predicate());
    Ok(!LdapPrincipal::from_query(ldap, &rootdse.root_domain_naming_context, Scope::Subtree, &filter)?.is_empty())
  }
  else
  {
    Ok(false)
  }
}

fn new_connection(scheme: impl Display, fqdn: &str, port: impl Display) -> Result<LdapConn, LdapError>
{
  let security_descriptor_flag_control = RawControl
  {
    ctype: "1.2.840.113556.1.4.801".to_owned(),
    crit: true,
    val: Some(vec![7])
  };
  let mut ldap = LdapConn::new(&format!("{}://{}:{}", scheme, fqdn, port))?;
  ldap.sasl_gssapi_bind(fqdn)?;
  ldap.with_controls(vec![security_descriptor_flag_control]);
  Ok(ldap)
}

fn connect_ldap(forest: String, tls: bool, rt: &Runtime) -> Option<LdapConn>
{
  let scheme = if tls { "ldaps" } else { "ldap" };
  let (conf, opts) = trust_dns_resolver::system_conf::read_system_conf().unwrap();
  let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<_>>::tokio(conf, opts).unwrap();
  
  let result = rt.block_on(async { resolver.srv_lookup(format!("_{}._tcp.gc._msdcs.{}", scheme, forest)).await }).unwrap();
  let mut records = result.iter()
    .group_by(|srv| srv.priority()).into_iter()
    .flat_map(|group| group.1.map(move |srv| (group.0, thread_rng().gen_range(1..64) * srv.weight(), srv)))
    .sorted_by(|a, b|
    {
      if a.0 == b.0
      {
        Ord::cmp(&b.1, &a.1)
      }
      else
      {
        Ord::cmp(&b.0, &a.0)
      }
    });
  loop
  {
    match records.next()
    {
      Some((_, _, record)) => match new_connection(scheme, &record.target().to_utf8(), record.port())
        {
          Ok(ldap) => break Some(ldap),
          Err(err) => log!(Level::Warn, "error connecting to {}:{} ({})", record.target(), record.port(), err)
        },
      None => break None
    }
  }
}

pub struct LdapManager
{
  ldap: LdapConn,
  rootdse: RootDSE,
  me: LdapPrincipal,
  group_cache: HashMap<SID, bool>
}

impl LdapManager
{
  pub fn new(forest: String, tls: bool, rt: &Runtime) -> Self
  {
    let mut ldap = connect_ldap(forest, tls, rt).unwrap();
    let rootdse = RootDSE::new(&mut ldap).unwrap().unwrap();
    let me = myself(&mut ldap, &rootdse).unwrap().unwrap();
    Self
    {
      ldap,
      rootdse,
      me,
      group_cache: HashMap::new()
    }
  }

  pub fn get_certificate_templates(&mut self) -> Result<Vec<LdapCertificateTemplate>, LdapError>
  {
    LdapCertificateTemplate::from_query(&mut self.ldap, &self.rootdse, Scope::OneLevel, "(objectClass=pKICertificateTemplate)", &self.me, &mut self.group_cache)
  }

  pub fn get_root_certificates(&mut self) -> Result<Vec<NamedCertificate>, LdapError>
  {
    let (rs, _) = self.ldap.search(&self.rootdse.certification_authorities, Scope::OneLevel, "(objectClass=certificationAuthority)", vec!["cACertificate", "cn"])?.success()?;
    Ok(rs.into_iter().filter_map(|result|
    {
      let result = SearchEntry::construct(result);
      match
      (
        result.attrs.get("cn").and_then(|v| v.iter().next()),
        result.bin_attrs.get("cACertificate").and_then(|v| v.iter().next().and_then(|v| match X509Certificate::from_der(v)
        {
          Ok(certificate) => Some(certificate),
          Err(err) => { log!(Level::Warn, "invalid root certificate: {}", err); None }
        }))
      )
      {
        (Some(cn), Some(certificate)) => Some(NamedCertificate { nickname: cn.to_owned(), certificate }),
        _ => None
      }
    }).collect::<Vec<_>>())
  }

  pub fn get_enrollment_service(&mut self) -> Result<Vec<LdapEnrollmentService>, LdapError>
  {
    LdapEnrollmentService::from_query(&mut self.ldap, &self.rootdse, Scope::OneLevel, "TODO FILTER TYPE")
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
          v.first().and_then(|bytes| match SID::new(bytes)
          {
            Ok(sid) => Some(sid),
            Err(err) => { log!(Level::Warn, "invalid sid: {}", err); None }
          })),
        rs.attrs.get("msDS-PrincipalName").and_then(|v| v.first().map(|v| v.to_owned())),
        rs.attrs.get("distinguishedName").and_then(|v| v.first().map(|v| v.to_owned())),
      )
      {
        (Some(object_sid), Some(principal_name), Some(distinguished_name)) => Some(Self { object_sid, principal_name, distinguished_name }),
        _ => None
      }
    }).collect::<Vec<Self>>())
  }
}

pub struct LdapCertificateTemplate
{
  cn: String,
  enroll: bool,
  auto_enroll: bool
}

impl LdapCertificateTemplate
{
  fn from_query(ldap: &mut LdapConn, rootdse: &RootDSE, scope: Scope, filter: &str, me: &LdapPrincipal, group_cache: &mut HashMap<SID, bool>) -> Result<Vec<Self>, LdapError>
  {
    let (results, _) = ldap.search(&rootdse.certificate_templates, scope, filter, vec!["cn", "nTSecurityDescriptor"])?.success()?;

    let mut predicate = |sid: &SID| -> Result<bool, LdapError>
    {
      if &me.object_sid == sid
      {
        Ok(true)
      }
      else
      {
        match group_cache.get(sid)
        {
          Some(result) => Ok(result.to_owned()),
          None =>
          {
            let result = is_member_of(ldap, rootdse, sid.clone(), me.object_sid.clone())?;
            group_cache.insert(sid.clone(), result);
            Ok(result)
          }
        }
      }
    };

    Ok(results.into_iter().filter_map(|result|
    {
      let result = SearchEntry::construct(result);
      let permissions = match result.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.iter().next())
      {
        Some(security_descriptor) =>
        {
          match SDDL::new(security_descriptor)
          {
            Ok(sddl) => Some((
              sddl.dacl.as_ref().unwrap().has_object_permission(&ENROLL, &mut predicate).unwrap(),
              sddl.dacl.as_ref().unwrap().has_object_permission(&AUTO_ENROLL, &mut predicate).unwrap())),
            Err(err) => { log!(Level::Warn, "invalid sddl: {}", err); None }
          }
        }
        None => None,
      };
      let cn = result.attrs.get("cn").and_then(|v| v.iter().next().map(|v| v.to_owned()));

      match (cn, permissions)
      {
        (Some(cn), Some((enroll, auto_enroll))) => Some(Self { cn, enroll, auto_enroll }),
        _ => None
      }
    }).collect::<Vec<_>>())
  }

  pub fn get_name(&self) -> &'_ str
  {
    &self.cn
  }
}

pub struct LdapEnrollmentService
{
  host_name: String,
  certificate: NamedCertificate,
  templates: Vec<String>
}

impl LdapEnrollmentService
{
  fn from_query(ldap: &mut LdapConn, rootdse: &RootDSE, scope: Scope, filter: &str) -> Result<Vec<Self>, LdapError>
  {
    let (rs, _) = ldap.search(&rootdse.enrollment_services, scope, filter, vec!["cn", "dNSHostName", "cACertificate", "certificateTemplates"])?.success()?;
    Ok(rs.into_iter().filter_map(|rs|
    {
      let rs = SearchEntry::construct(rs);
      match
      (
        rs.attrs.get("cn").and_then(|v| v.first().map(|v| v.to_owned())),
        rs.attrs.get("dNSHostName").and_then(|v| v.first().map(|v| v.to_owned())),
        rs.bin_attrs.get("cACertificate").and_then(|v| v.first().and_then(|v| match X509Certificate::from_der(v)
        {
          Ok(certificate) => Some(certificate),
          Err(err) => { log!(Level::Warn, "invalid enrollment service certificate: {}", err); None }
        })),
        rs.attrs.get("certificateTemplates").map(|v| v.to_vec())
      )
      {
        (Some(cn), Some(host_name), Some(certificate), Some(templates)) => Some(Self { host_name, certificate: NamedCertificate { nickname: cn, certificate }, templates }),
        _ => None
      }
    }).collect::<Vec<Self>>())
  }

  pub fn get_certificate(&self) -> &'_ NamedCertificate
  {
    &self.certificate
  }
}