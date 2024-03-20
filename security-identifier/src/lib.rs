#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;

use std::{fmt::{Debug, Display}, str::FromStr};
use nom::{branch::alt, bytes::complete::{tag, take}, character::complete::{digit1, hex_digit1}, combinator::{map_res, recognize}, multi::{many0, many_m_n}, number::complete::le_u32, Finish, IResult};
use thiserror::Error;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct SID
{
  identifier_authority: [u8; 6],
  sub_authority: Vec<u32>
}

impl SID
{
  pub fn new_from_bytes(input: &[u8]) -> Result<Self, SIDError>
  {
    let (remainder, sid) = parse_sid_bytes(input).finish()?;
    if !remainder.is_empty()
    {
      Err(SIDError::UnexpectedContent(format!("{:?}", remainder)))
    }
    else
    {
      Ok(sid)
    }
  }

  pub fn to_bytes(self) -> Vec<u8>
  {
    let mut result = Vec::with_capacity(8 + (self.sub_authority.len() * 4));
    result.push(1);
    result.push(self.sub_authority.len() as u8);
    for byte in self.identifier_authority
    {
      result.push(byte)
    }
    for sub_authority in self.sub_authority
    {
      for byte in sub_authority.to_le_bytes()
      {
        result.push(byte);
      }
    }
    result
  }

  pub fn to_ldap_predicate(self) -> String
  {
    let bytes = self.to_bytes();
    format!("(objectSID={})", bytes.into_iter().fold(String::new(), |a, byte| a + &format!("\\{:02x}", byte)))
  }
}

impl Display for SID
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    f.write_fmt(format_args!("S-1-"))?;
    if self.identifier_authority[0] == 0x00 && self.identifier_authority[1] == 0x00
    {
      f.write_fmt(format_args!("{}", BigEndian::read_u32(&self.identifier_authority[2..6])))?;
    }
    else
    {
      f.write_fmt(format_args!("{:#X}", BigEndian::read_u48(&self.identifier_authority)))?;
    }
    for sub_authority in &self.sub_authority
    {
      f.write_fmt(format_args!("-{}", sub_authority))?;
    }
    Ok(())
  }
}

impl FromStr for SID
{
  type Err = SIDError;

  fn from_str(input: &str) -> Result<Self, Self::Err>
  {
    let (remainder, sid) = parse_sid_str(input).finish()?;
    if !remainder.is_empty()
    {
      Err(SIDError::UnexpectedContent(remainder.to_owned()))
    }
    else
    {
      Ok(sid)
    }
  }
}

fn dec_u64(input : &str) -> IResult<&str, u64>
{
  map_res(recognize(digit1), str::parse)(input)
}

fn hex_u64(input : &str) -> IResult<&str, u64>
{
  let (input, _) = tag("0x")(input)?;
  map_res(recognize(hex_digit1), |x| { u64::from_str_radix(x, 16) })(input)
}

fn dec_u32(input : &str) -> IResult<&str, u32>
{
  map_res(recognize(digit1), str::parse)(input)
}

fn hex_u32(input : &str) -> IResult<&str, u32>
{
  let (input, _) = tag("0x")(input)?;
  map_res(recognize(hex_digit1), |x| { u32::from_str_radix(x, 16) })(input)
}

fn sid_segment(input: &str) -> IResult<&str, u32>
{
  let (input, _) = tag("-")(input)?;
  let (input, value) = alt((hex_u32, dec_u32))(input)?;
  Ok((input, value))
}

fn sid_identifier_authority(input: &str) -> IResult<&str, [u8; 6]>
{
  let mut identifier_authority = [0u8; 6];
  let (input, _) = tag("-")(input)?;
  let (input, value) = alt((hex_u64, dec_u64))(input)?;
  BigEndian::write_u48(&mut identifier_authority, value);
  Ok((input, identifier_authority))
}

fn parse_sid_str(input: &str) -> IResult<&str, SID>
{
  let (input, _) = tag::<_, _, nom::error::Error<_>>("S-1")(input)?;

  let (input, identifier_authority) = sid_identifier_authority(input)?;
  let (input, sub_authority) = many0(sid_segment)(input)?;

  Ok((input, SID { identifier_authority, sub_authority }))
}

fn parse_sid_bytes(input: &[u8]) -> IResult<&[u8], SID>
{
  let (input, _) = tag([1])(input)?;

  let (input, sub_authority_count) = nom::number::complete::u8(input)?;
  let (input, identifier_authority) = take(6usize)(input)?;
  let (input, sub_authority) = many_m_n(sub_authority_count as usize, sub_authority_count as usize, le_u32)(input)?;

  Ok((input, SID
  {
    identifier_authority: identifier_authority.try_into().unwrap(),
    sub_authority
  }))
}

#[derive(Error, Debug)]
pub enum SIDError
{
  #[error("bad revision")]
  BadRevision,

  #[error("parsing error: {0}")]
  ParseError(String),

  #[error("unexpected content: {0}")]
  UnexpectedContent(String)
}

impl<E> From<nom::error::Error<E>> for SIDError where E: Debug
{
  fn from(value: nom::error::Error<E>) -> Self
  {
    Self::ParseError(format!("{:?}: {:?}", value.code, value.input))
  }
}