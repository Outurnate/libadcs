mod operations;

use std::{env::{self, VarError}, process::exit, fmt::Display};
use bcder::{Mode, decode::{Constructed, DecodeError, BytesSource, Source}};
use bytes::Bytes;
use libadcs::NamedCertificate;
use operations::Operations;
use pem::PemError;
use thiserror::Error;
use x509_certificate::{rfc2986::CertificationRequest, CapturedX509Certificate};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Environment
{
  #[arg(short, long)]
  realm: String,

  #[arg(short, long)]
  endpoint: String,

  #[clap(flatten)]
  verbose: clap_verbosity_flag::Verbosity,
}
trait CertmongerOutput
{
  fn output(self) -> (i32, String);
}

#[derive(Error, Debug)]
pub enum Error
{
  #[error("connection error: {0}")]
  ConnectionError(String),         // 3
  #[error("underconfigured: {0}")]
  Underconfigurated(String),       // 4
  #[error("bad environment variable: {0}")]
  BadEnvironment(#[from] VarError),
  #[error("bad pem encoding: {0}")]
  BadPemEncoding(#[from] PemError),
  #[error("bad pem contents: {0}")]
  BadPemData(#[from] DecodeError<<BytesSource as Source>::Error>)
}

impl CertmongerOutput for Error
{
  fn output(self) -> (i32, String)
  {
    match self
    {
      Error::ConnectionError(_) => (3, self.to_string()),
      Error::Underconfigurated(_) => (4, self.to_string()),
      _ => (-1, self.to_string())
    }
  }
}

pub enum EnrollmentResponse
{
  Issued(CapturedX509Certificate), // 0
  WaitABit(String),                // 1
  Rejected(String),                // 2
  WaitABitMore(u64, String)        // 5
}

impl CertmongerOutput for EnrollmentResponse
{
  fn output(self) -> (i32, String)
  {
    match self
    {
      EnrollmentResponse::Issued(certificate) => (0, certificate.encode_pem()),
      EnrollmentResponse::WaitABit(message) => (1, message),
      EnrollmentResponse::Rejected(message) => (2, message),
      EnrollmentResponse::WaitABitMore(seconds, message) => (5, format!("{}\n{}", seconds, message)),
    }
  }
}

pub struct RootCertificates
{
  primary_root_certificate: Option<NamedCertificate>,
  supplementary_root_certificates: Vec<NamedCertificate>,
  chain_certificates: Vec<NamedCertificate>
}

impl Display for RootCertificates
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    if let Some(root) = &self.primary_root_certificate
    {
      root.fmt(f)?;
    }
    f.write_str("\n")?;
    for certificate in self.supplementary_root_certificates.iter()
    {
      certificate.fmt(f)?;
    }
    f.write_str("\n")?;
    for certificate in self.chain_certificates.iter()
    {
      certificate.fmt(f)?;
    }
    Ok(())
  }
}

fn certmonger_submit(env: Environment) -> Result<(i32, String), Error>
{
  let operations = Operations::new(env)?;
  match env::var("CERTMONGER_OPERATION")?.as_str()
  {
    "SUBMIT" =>
    {
      let csr = Constructed::decode(Bytes::copy_from_slice(&pem::parse(env::var("CERTMONGER_CSR")?)?.contents), Mode::Der, |der| CertificationRequest::take_from(der))?;
      let ca_profile = env::var("CERTMONGER_CA_PROFILE")?;

      Ok(operations.submit(csr, ca_profile)?.output())
    },
    "POLL" =>
    {
      let ca_cookie = env::var("CERTMONGER_CA_COOKIE")?;

      Ok(operations.poll(ca_cookie)?.output())
    },
    "IDENTIFY" => Ok((0, operations.identify()?)),
    "FETCH-ROOTS" => Ok((0, operations.fetch_roots()?.to_string())),
    "GET-NEW-REQUEST-REQUIREMENTS" | "GET-RENEW-REQUEST-REQUIREMENTS" => Ok((0, operations.new_or_renew_requirements()?.join("\n"))),
    "GET-SUPPORTED-TEMPLATES" => Ok((0, operations.supported_templates()?.join("\n"))),
    _ => Ok((6, String::new()))
  }
}

fn main()
{
  let env = Environment::parse();
  simple_logger::init_with_level(env.verbose.log_level().unwrap_or(log::Level::Error)).unwrap();
  let (code, out) = match certmonger_submit(env).map_err(|err| err.output())
  {
    Ok(x) => x,
    Err(x) => x,
  };
  println!("{}", out);
  exit(code);
}