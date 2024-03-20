use std::future::Future;

use itertools::Itertools;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError};
use rand::{thread_rng, Rng};
use tokio::task::JoinHandle;
use tracing::{event, instrument, Level};
use trust_dns_resolver::{name_server::{GenericConnector, TokioRuntimeProvider}, proto::rr::rdata::SRV, lookup::SrvLookup, error::ResolveError, AsyncResolver};


#[instrument(skip(conn))]
fn drive_ldap(conn: LdapConnAsync) -> JoinHandle<()>
{
  tokio::spawn(async move
    {
      if let Err(e) = conn.drive().await
      {
        event!(Level::WARN, "LDAP connection error: {}", e);
      }
    })
}

fn srv_records_in_order(result: &'_ SrvLookup) -> impl Iterator<Item = &'_ SRV>
{
  result.iter()
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
    })
    .map(|(_, _, srv)| srv)
}

#[derive(Debug)]
pub struct LdapSearchOptions
{
  explicit_tls: bool,
  global_catalog: bool
}

impl LdapSearchOptions
{
  fn build_ldap_url(&self, domain: &str) -> String
  {
    let scheme = if self.explicit_tls { "ldaps" } else { "ldap" };
    let gc = if self.global_catalog { "gc._msdcs." } else { "" };
    format!("_{}._tcp.{}{}", scheme, gc, domain)
  }
}

#[instrument(skip(binder, settings))]
pub async fn try_all_ldap_servers<Fut>(mut realm: String, options: LdapSearchOptions, settings: LdapConnSettings, binder: impl Fn(&mut Ldap) -> Fut) -> Result<Option<(JoinHandle<()>, Ldap)>, ResolveError>
  where Fut: Future<Output = Result<(), LdapError>>
{
  let scheme = if options.explicit_tls { "ldaps" } else { "ldap" };
  let resolver = AsyncResolver::<GenericConnector<TokioRuntimeProvider>>::tokio_from_system_conf()?;

  if realm.ends_with('.')
  {
    realm.pop();
  }

  let names: Vec<_> = realm.split('.').collect();

  // get a list of top level domains to try
  // e.g. for SUB.DOMAIN.COM, try:
  // - SUB.DOMAIN.COM
  // - DOMAIN.COM
  // - COM
  let domains = (0..names.len()).map(|i| names[i..].join("."));

  for domain in domains
  {
    // look up SRV records for the domain and iterate over them
    let result = resolver.srv_lookup(options.build_ldap_url(&domain)).await?;
    for record in srv_records_in_order(&result)
    {
      // try the connection
      let ldap_server = record.target().to_utf8();
      let ldap_port = record.port();
      match LdapConnAsync::with_settings(settings.clone(), &format!("{}://{}:{}", scheme, &ldap_server, ldap_port)).await
      {
        Err(err) =>
        {
          event!(Level::INFO, "connect to {}:{} failed: {}", ldap_server, ldap_port, err);
        },
        Ok((conn, mut ldap)) =>
        {
          // start the background driver and call into the binder
          let handle = drive_ldap(conn);
          if let Err(err) = binder(&mut ldap).await
          {
            event!(Level::INFO, "bind to {}:{} failed: {}", ldap_server, ldap_port, err);
            handle.abort();
            let _ = handle.await;
            continue;
          }
          else
          {
            event!(Level::INFO, "selected {}:{}", ldap_server, ldap_port);
            return Ok(Some((handle, ldap)))
          }
        }
      }
    }
  }

  Ok(None)
}