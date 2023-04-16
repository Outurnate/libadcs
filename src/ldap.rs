use std::collections::HashMap;
use std::fmt::Display;

use bcder::Oid;
use itertools::Itertools;
use ldap3::controls::RawControl;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::{Scope, SearchEntry, LdapError, LdapConn};
use log::{log, Level};
use tokio::runtime::Runtime;
use trust_dns_resolver::ConnectionProvider;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::proto::DnsHandle;
use crate::client::{EnrollmentService, CertificateTemplate};
use crate::{NamedCertificate, AdcsError};
use crate::cmc::rfc5272::AttributeValue;
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
    if let Some(rootdse) = rs.into_iter().next().map(SearchEntry::construct)
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
          enrollment_services: format!("CN=Enrollment Services,CN=Public Key Services,CN=Services,{}", configuration_naming_context)
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
  let netbios_name = rs.authzid.split(':').nth(1);
  let sam_account_name = netbios_name.and_then(|netbios_name| netbios_name.split('\\').nth(1));

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

fn try_global_catalog(scheme: impl Display, fqdn: &str, port: impl Display) -> Option<LdapConn>
{
  fn inner(scheme: impl Display, fqdn: &str, port: impl Display) -> Result<LdapConn, LdapError>
  {
    let security_descriptor_flag_control = RawControl
    {
      ctype: "1.2.840.113556.1.4.801".to_owned(),
      crit: true,
      val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07])
    };
    let mut ldap = LdapConn::new(&format!("{}://{}:{}", scheme, fqdn, port))?;
    ldap.sasl_gssapi_bind(fqdn)?;
    ldap.with_controls(vec![security_descriptor_flag_control]);
    log!(Level::Info, "selected {} on port {}", fqdn, port);
    Ok(ldap)
  }

  let result = if fqdn.ends_with('.')
  {
    let mut temp = fqdn.to_owned();
    temp.pop();
    inner(scheme, &temp, &port)
  }
  else
  {
    inner(scheme, fqdn, &port)
  };

  match result
  {
    Ok(conn) => Some(conn),
    Err(err) => { log!(Level::Warn, "error connecting to {} on port {} ({})", fqdn, port, err); None }
  }
}

fn try_all_global_catalog<C: DnsHandle<Error = ResolveError>, P: ConnectionProvider<Conn = C>>(resolver: &AsyncResolver<C, P>, rt: &Runtime, scheme: impl Display, domain: &str) -> Option<LdapConn>
{
  fn inner<C: DnsHandle<Error = ResolveError>, P: ConnectionProvider<Conn = C>>(resolver: &AsyncResolver<C, P>, rt: &Runtime, scheme: impl Display, domain: &str) -> Result<Option<LdapConn>, ResolveError>
  {
    let result = rt.block_on(async { resolver.srv_lookup(format!("_{}._tcp.gc._msdcs.{}", scheme, domain)).await })?;
    let records = result.iter()
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
    for (_, _, record) in records
    {
      if let Some(conn) = try_global_catalog(&scheme, &record.target().to_utf8(), record.port())
      {
        return Ok(Some(conn))
      }
    }
    Ok(None)
  }

  match inner(resolver, rt, scheme, domain)
  {
    Ok(conn) => conn,
    Err(err) => { log!(Level::Warn, "error resolving {}: {}", domain, err); None }
  }
}

fn try_all_ldap_servers(mut realm: String, tls: bool) -> Option<LdapConn>
{
  let rt  = Runtime::new().expect("couldn't initialize tokio runtime");
  let scheme = if tls { "ldaps" } else { "ldap" };
  let (conf, opts) = trust_dns_resolver::system_conf::read_system_conf().expect("couldn't read system dns config");
  let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<_>>::tokio(conf, opts).expect("error constructing dns resolver");

  if realm.ends_with('.')
  {
    realm.pop();
  }

  let names: Vec<_> = realm.split('.').collect();
  for i in 0..names.len()
  {
    let domain = names[i..].join(".");
    if let Some(conn) = try_all_global_catalog(&resolver, &rt, scheme, &domain)
    {
      return Some(conn)
    }
  }
  None
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
  pub fn new(realm: String, tls: bool) -> Result<Self, AdcsError>
  {
    if let Some(mut ldap) = try_all_ldap_servers(realm.clone(), tls)
    {
      log!(Level::Info, "found ldap global catalog for realm {} (using tls: {})", realm, tls);
      if let Some(rootdse) = RootDSE::new(&mut ldap)?
      {
        log!(Level::Info, "found rootdse");
        if let Some(me) = myself(&mut ldap, &rootdse)?
        {
          log!(Level::Info, "found myself in ldap");
          Ok(Self
            {
              ldap,
              rootdse,
              me,
              group_cache: HashMap::new()
            })
        }
        else
        {
          Err(AdcsError::NoMyself)
        }
      }
      else
      {
        Err(AdcsError::NoRootDSE)
      }
    }
    else
    {
      Err(AdcsError::NoGlobalCatalogServer)
    }
  }

  pub fn get_certificate_templates(&mut self) -> Result<Vec<CertificateTemplate>, LdapError>
  {
    let (results, _) = self.ldap.search(&self.rootdse.certificate_templates, Scope::OneLevel, "(objectClass=pKICertificateTemplate)", vec!["cn", "nTSecurityDescriptor"])?.success()?;

    let mut predicate = |sid: &SID| -> Result<bool, LdapError>
    {
      if &self.me.object_sid == sid
      {
        Ok(true)
      }
      else
      {
        match self.group_cache.get(sid)
        {
          Some(result) => Ok(result.to_owned()),
          None =>
          {
            let result = is_member_of(&mut self.ldap, &self.rootdse, sid.clone(), self.me.object_sid.clone())?;
            self.group_cache.insert(sid.clone(), result);
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
        (Some(cn), Some((enroll, auto_enroll))) => Some(CertificateTemplate { cn, enroll, auto_enroll }),
        _ => None
      }
    }).collect())
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
        (Some(cn), Some(certificate)) =>
        {
          log!(Level::Info, "found root cert {}", cn);
          Some(NamedCertificate { nickname: cn.to_owned(), certificate })
        },
        _ => None
      }
    }).collect::<Vec<_>>())
  }

  pub fn get_enrollment_service(&mut self) -> Result<Vec<EnrollmentService<String>>, LdapError>
  {
    let (rs, _) = self.ldap.search(&self.rootdse.enrollment_services, Scope::OneLevel, "(objectClass=pKIEnrollmentService)", vec!["cn", "dNSHostName", "cACertificate", "certificateTemplates"])?.success()?;
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
        (Some(cn), Some(host_name), Some(certificate), Some(templates)) =>
        {
          log!(Level::Info, "found enrollment service {}", cn);
          Some(EnrollmentService { endpoint: host_name, certificate: NamedCertificate { nickname: cn, certificate }, template_names: templates })
        },
        _ => None
      }
    }).collect())
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