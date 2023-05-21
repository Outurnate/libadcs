use bytes::Bytes;
use cross_krb5::{ClientCtx, InitiateFlags, Step, PendingClientCtx};
use reqwest::{blocking::{Client, Body}, IntoUrl, StatusCode, header::{self, ToStrError}};
use base64::{Engine as _, engine::general_purpose};
use thiserror::Error;
use tracing::{instrument, event, Level};
use url::ParseError;

use super::{SoapBody, schema::Header};

#[derive(Error, Debug)]
pub enum SoapHttpError
{
  #[error("http request error: {0}")]
  HttpTransport(#[from] reqwest::Error),

  #[error("invalid http response: {0}")]
  InvalidHttpResponse(StatusCode),

  #[error("authorize header decode error: {0}")]
  InvalidBase64(#[from] base64::DecodeError),

  #[error("authorize header contains invalid utf8: {0}")]
  InvalidUtf8(#[from] ToStrError),

  #[error("gssapi error: {0}")]
  Gssapi(#[from] anyhow::Error),

  #[error("http response didn't contain www-authenticate header")]
  NoAuthenticateHeader,

  #[error("soap protocol fault: {0}")]
  SoapTransport(#[from] super::SoapError),

  #[error("soap action is not a valid url: {0}")]
  SoapActionParse(#[from] ParseError),

  #[error("soap envelope isn't addressed to anyone")]
  SoapNotAddressed
}

pub struct SoapClient
{
  http_client: Client
}

impl SoapClient
{
  pub fn new() -> Self
  {
    Self { http_client: Client::new() }
  }

  #[instrument(skip(self, header), err, ret)]
  pub fn invoke<S: SoapBody, R: SoapBody>(&self, header: &Header, body: &S) -> Result<R, SoapHttpError>
  {
    if let Some(to) = header.get_to()?
    {
      let mut request = SoapClientRequest::new(&self.http_client, &format!("HTTP/{}", to.host_str().unwrap_or_default()))?;
      let body = body.clone_to_soap(header)?;
      let response = loop
      {
        match request.step(to.as_str(), body.clone())?
        {
          Some(bytes) => break bytes,
          None => continue
        }
      };
      event!(Level::DEBUG, "{}", String::from_utf8_lossy(&response));
      Ok(R::from_soap(&*response)?.1)
    }
    else
    {
      Err(SoapHttpError::SoapNotAddressed)
    }
  }
}

struct SoapClientRequest<'a>
{
  http_client: &'a Client,
  kerberos_client: Option<PendingClientCtx>,
  token: Vec<u8>
}

impl<'a> SoapClientRequest<'a>
{
  fn new(http_client: &'a Client, spn: &str) -> Result<Self, SoapHttpError>
  {
    let (client, token) = ClientCtx::new(InitiateFlags::empty(), None, spn, None)?;
    Ok(Self
    {
      http_client,
      kerberos_client: Some(client),
      token: token.to_owned()
    })
  }

  #[instrument(skip(self, token), err)]
  fn post(&self, endpoint: impl IntoUrl + std::fmt::Debug, body: impl Into<Body> + std::fmt::Debug, token: &[u8]) -> Result<(Vec<u8>, StatusCode, Bytes), SoapHttpError>
  {
    event!(Level::TRACE, "posting to endpoint");
    let res = self.http_client.post(endpoint)
      .header(header::AUTHORIZATION, format!("Negotiate {}", general_purpose::STANDARD.encode(token)))
      .header(header::CONTENT_TYPE, "application/soap+xml")
      .body(body)
      .send()?;
    if let Some(token) = res.headers().get("WWW-Authenticate").and_then(|auth|
    {
      auth
        .to_str()
        .map(|value|
        {
          value
            .split_whitespace()
            .last()
            .map(|value| general_purpose::STANDARD.decode(value))
        })
        .transpose()
    })
    {
      event!(Level::TRACE, "WWW-Authenticate header is valid");
      Ok((token??, res.status(), res.bytes()?))
    }
    else
    {
      event!(Level::TRACE, "WWW-Authenticate header is invalid or missing");
      Err(SoapHttpError::NoAuthenticateHeader)
    }
  }

  #[instrument(skip(self), err)]
  fn step(&mut self, endpoint: impl IntoUrl + std::fmt::Debug, body: impl Into<Body> + std::fmt::Debug) -> Result<Option<Bytes>, SoapHttpError>
  {
    let (received_token, status, body) = self.post(endpoint, body, &self.token)?;
    match status
    {
      StatusCode::OK =>
      {
        event!(Level::TRACE, "Server accepted GSSAPI token");
        Ok(Some(body))
      },
      StatusCode::UNAUTHORIZED => if let Some(kerberos_client) = self.kerberos_client.take()
      {
        match kerberos_client.step(&received_token)?
        {
          Step::Continue((kerberos_client, token)) =>
          {
            event!(Level::TRACE, "Server responded with token requiring another step");
            self.kerberos_client = Some(kerberos_client);
            self.token = token.to_owned();
            Ok(None)
          },
          Step::Finished((_, token)) =>
          {
            if let Some(token) = token
            {
              event!(Level::TRACE, "GSSAPI client reported finished, next request must be accepted");
              self.kerberos_client = None;
              self.token = token.to_owned();
              Ok(None)
            }
            else
            {
              event!(Level::TRACE, "GSSAPI finished without token");
              Ok(Some(body))
            }
          }
        }
      }
      else
      {
        event!(Level::TRACE, "Server replied unauthorized, but GSSAPI doesn't have another step");
        Ok(None)
      },
      status => Err(SoapHttpError::InvalidHttpResponse(status))
    }
  }
}