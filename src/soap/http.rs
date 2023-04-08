use bytes::Bytes;
use cross_krb5::{ClientCtx, InitiateFlags, Step, PendingClientCtx};
use reqwest::{blocking::{Client, Body}, IntoUrl, StatusCode, header};
use base64::{Engine as _, engine::general_purpose};
use thiserror::Error;

use super::{SoapBody, schema::Header};

#[derive(Error, Debug)]
pub enum Error
{
  #[error("http request error: {0}")]
  HttpTransport(#[from] reqwest::Error),
  #[error("invalid http response: {0}")]
  InvalidHttpResponse(StatusCode),
  #[error("header decode error: {0}")]
  InvalidBase64(#[from] base64::DecodeError),
  #[error("gssapi error: {0}")]
  Gssapi(#[from] anyhow::Error),
  #[error("http response didn't contain www-authenticate header")]
  NoAuthenticateHeader
}

struct SoapClient
{
  http_client: Client
}

impl SoapClient
{
  fn new() -> Self
  {
    Self { http_client: Client::new() }
  }

  fn invoke<S: SoapBody, R: SoapBody>(&self, header: &Header, body: &S) -> Result<R, Error>
  {
    let spn = ""; // TODO
    let mut request = SoapClientRequest::new(&self.http_client, spn)?;
    let body = body.clone_to_soap(header).unwrap();
    let response = loop
    {
      match request.step(header.get_action().unwrap(), body.clone())?
      {
        Some(bytes) => break bytes,
        None => continue
      }
    };
    Ok(R::from_soap(&*response).unwrap().1)
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
  fn new(http_client: &'a Client, spn: &str) -> Result<Self, Error>
  {
    let (client, token) = ClientCtx::new(InitiateFlags::empty(), None, spn, None)?;
    Ok(Self
    {
      http_client,
      kerberos_client: Some(client),
      token: token.to_owned()
    })
  }

  fn post(&self, endpoint: impl IntoUrl, body: impl Into<Body>, token: &[u8]) -> Result<(Vec<u8>, StatusCode, Bytes), Error>
  {
    let res = self.http_client.post(endpoint)
      .header(header::AUTHORIZATION, format!("Negotiate {}", general_purpose::STANDARD_NO_PAD.encode(token)))
      .body(body)
      .send()?;
    if let Some(token) = res.headers().get("WWW-Authenticate").and_then(|auth|
    {
      let auth = auth.as_bytes();
      auth
        .iter()
        .position(|ch| *ch == b' ')
        .map(|split_point| general_purpose::STANDARD_NO_PAD.decode(auth.split_at(split_point).1))
    })
    {
      Ok((token?, res.status(), res.bytes()?))
    }
    else
    {
      Err(Error::NoAuthenticateHeader)
    }
  }

  fn step(&mut self, endpoint: impl IntoUrl, body: impl Into<Body>) -> Result<Option<Bytes>, Error>
  {
    let (received_token, status, body) = self.post(endpoint, body, &self.token)?;
    match status
    {
      StatusCode::ACCEPTED =>
      {
        Ok(Some(body))
      },
      StatusCode::UNAUTHORIZED => if let Some(kerberos_client) = self.kerberos_client.take()
      {
        match kerberos_client.step(&received_token)?
        {
          Step::Continue((kerberos_client, token)) =>
          {
            self.kerberos_client = Some(kerberos_client);
            self.token = token.to_owned();
            Ok(None)
          },
          Step::Finished((_, token)) =>
          {
            if let Some(token) = token
            {
              self.kerberos_client = None;
              self.token = token.to_owned();
              Ok(None)
            }
            else
            {
              Ok(Some(body))
            }
          }
        }
      }
      else
      {
        Ok(None)
      },
      status => Err(Error::InvalidHttpResponse(status))
    }
  }
}