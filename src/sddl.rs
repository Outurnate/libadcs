use bitflags::bitflags;
use thiserror::Error;
use uuid::Uuid;
use uuid::uuid;

#[derive(Error, Debug)]
pub enum SDDLError
{
  #[error("bad revision")]
  BadRevision,
  #[error("sddl is not self-relative")]
  NotSelfRelative,
  #[error("field {field_name:?} at {field_index:?} with length {field_size:?} is out of input bounds (length {input_length:?})")]
  FieldOutOfBounds
  {
    field_name: String,
    field_index: usize,
    field_size: usize,
    input_length: usize
  },
  #[error("offset of {offset:?} from field {field_name:?} (length: {field_size:?}) out of bound {length:?}")]
  OffsetOutOfBounds
  {
    field_name: String,
    offset: usize,
    field_size: Option<usize>,
    length: usize
  },
  #[error("invalid value {value:?} for field {field_name:?}")]
  BadValue
  {
    field_name: String,
    value: u64
  },
  #[error("invalid ace_type value")]
  InvalidACEType(u8),
  #[error("bad uuid")]
  BadUUID(#[from] uuid::Error)
}

fn clone_into_array<A: Sized + Default + AsMut<[T]>, T: Clone>(slice: &[T]) -> A
{
  let mut a = Default::default();
  <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
  a
}

fn field_u8(input: &[u8], field_name: &str, field_index: usize) -> Result<u8, SDDLError>
{
  if (input.len() - 1 + 1) > field_index
  {
    Ok(input[field_index])
  }
  else
  {
    Err(SDDLError::FieldOutOfBounds { field_name: field_name.to_owned(), field_index, field_size: 1, input_length: input.len() })
  }
}

fn le_field_u16(input: &[u8], field_name: &str, field_index: usize) -> Result<u16, SDDLError>
{
  if (input.len() - 1) > field_index
  {
    Ok(u16::from_le_bytes(clone_into_array(&input[field_index..(field_index + 2)])))
  }
  else
  {
    Err(SDDLError::FieldOutOfBounds { field_name: field_name.to_owned(), field_index, field_size: 2, input_length: input.len() })
  }
}

fn le_field_u32(input: &[u8], field_name: &str, field_index: usize) -> Result<u32, SDDLError>
{
  if (input.len() - 3) > field_index
  {
    Ok(u32::from_le_bytes(clone_into_array(&input[field_index..(field_index + 4)])))
  }
  else
  {
    Err(SDDLError::FieldOutOfBounds { field_name: field_name.to_owned(), field_index, field_size: 4, input_length: input.len() })
  }
}

fn field_subslice<'a>(input: &'a[u8], field_name: &str, offset: usize) -> Result<&'a[u8], SDDLError>
{
  if input.len() > offset
  {
    Ok(&input[offset..])
  }
  else
  {
    Err(SDDLError::OffsetOutOfBounds { field_name: field_name.to_owned(), offset, length: input.len(), field_size: None })
  }
}

fn field_subslice_length<'a>(input: &'a[u8], field_name: &str, offset: usize, length: usize) -> Result<&'a[u8], SDDLError>
{
  if input.len() > offset && input.len() >= (offset + length)
  {
    Ok(&input[offset..(offset + length)])
  }
  else
  {
    Err(SDDLError::OffsetOutOfBounds { field_name: field_name.to_owned(), offset, length: input.len(), field_size: Some(length) })
  }
}

fn field_uuid(input: &[u8], field_name: &str, offset: usize) -> Result<Uuid, SDDLError>
{
  let raw = field_subslice_length(input, field_name, offset, 16)?;
  Ok(Uuid::from_bytes(
    [
      raw[3], raw[2], raw[1], raw[0],
      raw[5], raw[4],
      raw[7], raw[6],
      raw[8], raw[9],
      raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    ]))
}

fn check_revision(input: u8, revision: u8) -> Result<(), SDDLError>
{
  if input != revision { Err(SDDLError::BadRevision) } else { Ok(()) }
}

bitflags!
{
  #[repr(transparent)]
  #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
  pub struct AccessMask: u32
  {
    const ADS_RIGHT_DS_CREATE_CHILD   = 0x0000_0001;
    const ADS_RIGHT_DS_SELF           = 0x0000_0008;
    const ADS_RIGHT_DS_READ_PROP      = 0x0000_0010;
    const ADS_RIGHT_DS_WRITE_PROP     = 0x0000_0020;
    const ADS_RIGHT_DS_CONTROL_ACCESS = 0x0000_0100;
    const DELETE                      = 0x0001_0000;
    const READ_CONTROL                = 0x0002_0000;
    const WRITE_DAC                   = 0x0004_0000;
    const WRITE_OWNER                 = 0x0008_0000;
    const SYNCHRONIZE                 = 0x0010_0000;
    const STANDARD_RIGHTS_REQUIRED    = 0x000F_0000;
    const STANDARD_RIGHTS_READ        = Self::READ_CONTROL.bits();
    const STANDARD_RIGHTS_WRITE       = Self::READ_CONTROL.bits();
    const STANDARD_RIGHTS_EXECUTE     = Self::READ_CONTROL.bits();
    const SPECIFIC_RIGHTS_ALL         = 0x0000_FFFF;
    const STANDARD_RIGHTS_ALL         = 0x001F_0000;
  }
}

impl AccessMask
{
  fn field(input: &[u8], field_index: usize) -> Result<Self, SDDLError>
  {
    let value = le_field_u32(input, "access_mask", field_index)?;
    match Self::from_bits(value)
    {
      Some(flags) => Ok(flags),
      None => Err(SDDLError::BadValue { field_name: "access_mask".to_owned(), value: value as u64 })
    }
  }
}

bitflags!
{
  #[repr(transparent)]
  #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
  pub struct AccessObjectFlags: u32
  {
    const NONE                              = 0x0000_0000;
    const ACE_OBJECT_TYPE_PRESENT           = 0x0000_0001;
    const ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x0000_0002;
  }
}

impl AccessObjectFlags
{
  fn field(input: &[u8], field_index: usize) -> Result<Self, SDDLError>
  {
    let value = le_field_u32(input, "access_object_flags", field_index)?;
    match Self::from_bits(value)
    {
      Some(flags) => Ok(flags),
      None => Err(SDDLError::BadValue { field_name: "access_object_flags".to_owned(), value: value as u64 })
    }
  }
}

bitflags!
{
  #[repr(transparent)]
  #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
  pub struct ACEFlags: u8
  {
    const NONE                  = 0b0000_0000;
    const OBJECT_INHERIT        = 0b0000_0001;
    const CONTAINER_INHERIT     = 0b0000_0010;
    const NO_PROPAGATE_INHERITE = 0b0000_0100;
    const INHERIT_ONLY          = 0b0000_1000;
    const INHERITED             = 0b0001_0000;
    const SUCCESSFUL_ACCESS     = 0b0100_0000;
    const FAILED_ACCESS         = 0b1000_0000;
    const AUDIT_FLAGS           = Self::FAILED_ACCESS.bits() | Self::SUCCESSFUL_ACCESS.bits();
    const INHERITANCE_FLAGS     = Self::INHERIT_ONLY.bits() | Self::NO_PROPAGATE_INHERITE.bits() | Self::CONTAINER_INHERIT.bits() | Self::OBJECT_INHERIT.bits();
  }
}

impl ACEFlags
{
  fn field(input: &[u8], field_index: usize) -> Result<Self, SDDLError>
  {
    let value = field_u8(input, "ace_flags", field_index)?;
    match Self::from_bits(value)
    {
      Some(flags) => Ok(flags),
      None => Err(SDDLError::BadValue { field_name: "ace_flags".to_owned(), value: value as u64 })
    }
  }
}

bitflags!
{
  #[repr(transparent)]
  #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
  pub struct ControlFlags: u16
  {
    const OWNER_DEFAULTED           = 0b0000_0000_0000_0001;
    const GROUP_DEFAULTED           = 0b0000_0000_0000_0010;
    const DACL_PRESENT              = 0b0000_0000_0000_0100;
    const DACL_DEFAULTED            = 0b0000_0000_0000_1000;

    const SACL_PRESENT              = 0b0000_0000_0001_0000;
    const SACL_DEFAULTED            = 0b0000_0000_0010_0000;
    const SERVER_SECURITY           = 0b0000_0000_0100_0000;
    const DACL_TRUSTED              = 0b0000_0000_1000_0000;

    const DACL_INHERITANCE_REQUIRED = 0b0000_0001_0000_0000;
    const INHERITANCE_REQUIRED      = 0b0000_0010_0000_0000;
    const DACL_AUTO_INHERITED       = 0b0000_0100_0000_0000;
    const SACL_AUTO_INHERITED       = 0b0000_1000_0000_0000;

    const DACL_PROTECTED            = 0b0001_0000_0000_0000;
    const SACL_PROTECTED            = 0b0010_0000_0000_0000;
    const CONTROL_VALID             = 0b0100_0000_0000_0000;
    const SELF_RELATIVE             = 0b1000_0000_0000_0000;
  }
}

impl ControlFlags
{
  fn field(input: &[u8], field_index: usize) -> Result<Self, SDDLError>
  {
    let value = le_field_u16(input, "control_flags", field_index)?;
    match Self::from_bits(value)
    {
      Some(flags) => Ok(flags),
      None => Err(SDDLError::BadValue { field_name: "control_flags".to_owned(), value: value as u64 })
    }
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct AccessObject
{
  pub access_mask: AccessMask,
  pub flags: AccessObjectFlags,
  pub object_type: Option<Uuid>,
  pub inherited_object_type: Option<Uuid>,
  pub subject: SID
}

impl AccessObject
{
  fn new(input: &[u8]) -> Result<Self, SDDLError>
  {
    let flags = AccessObjectFlags::field(input, 4)?;
    let object_type_present = flags.contains(AccessObjectFlags::ACE_OBJECT_TYPE_PRESENT);
    let inherited_object_type_present = flags.contains(AccessObjectFlags::ACE_INHERITED_OBJECT_TYPE_PRESENT);
    let (object_type, inherited_object_type, sid_start) = match (object_type_present, inherited_object_type_present)
    {
      (true, false)  => (Some(field_uuid(input, "object_type", 8)?), None, 24),
      (false, true)  => (None, Some(field_uuid(input, "inherited_object_type", 8)?), 24),
      (true, true)   => (Some(field_uuid(input, "object_type", 8)?), Some(field_uuid(input, "inherited_object_type", 24)?), 40),
      (false, false) => (None, None, 8)
    };
    Ok(Self
    {
      access_mask: AccessMask::field(input, 0)?,
      flags,
      object_type,
      inherited_object_type,
      subject: SID::new(&input[sid_start..])?
    })
  }

  fn is_object_type(&self, object_type: &Uuid) -> bool
  {
    self.object_type.map(|o| o == *object_type).unwrap_or(false) ||
    self.inherited_object_type.map(|o| o == *object_type).unwrap_or(false)
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct SID
{
  identifier_authority: [u8; 6],
  sub_authority: Vec<u32>
}

impl SID
{
  pub fn new(input: &[u8]) -> Result<Self, SDDLError>
  {
    check_revision(field_u8(input, "revision", 0)?, 1)?;
    let sub_authority_count = field_u8(input, "sub_authority_count", 1)? as usize;
    Ok(Self
    {
      identifier_authority: clone_into_array(field_subslice_length(input, "identifier_authority", 2, 6)?),
      sub_authority: field_subslice_length(input, "sub_authority", 8, sub_authority_count * 4)?.windows(4).step_by(4).map(|sub| u32::from_le_bytes(sub.try_into().unwrap())).collect::<Vec<u32>>()
    })
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
    format!("(objectSID={})", bytes.into_iter().fold(String::new(), |a, byte| a + &format!("\\{}", hex::encode(&[byte]))))
  }
}

impl std::fmt::Display for SID
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    f.write_fmt(format_args!("S-1-"))?;
    if self.identifier_authority[0] == 0x00 && self.identifier_authority[1] == 0x00
    {
      f.write_fmt(format_args!("{}", u32::from_be_bytes(self.identifier_authority[2..6].try_into().unwrap())))?;
    }
    else
    {
      f.write_fmt(format_args!("0x{}", hex::encode_upper(self.identifier_authority)))?;
    }
    for sub_authority in &self.sub_authority
    {
      f.write_fmt(format_args!("-{}", sub_authority))?;
    }
    Ok(())
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ACL(Vec<ACE>);

impl ACL
{
  fn new(input: &[u8]) -> Result<Self, SDDLError>
  {
    check_revision(field_u8(input, "revision", 0)?, 4)?;
    let ace_count = le_field_u16(input, "ace_count", 4)? as usize;
    let mut ace_start = 8;
    let mut ace_list = Vec::with_capacity(ace_count);
    for _ in 0..ace_count
    {
      let ace = ACE::new(field_subslice(input, "ace_offset", ace_start)?)?;
      ace_start += ace.size as usize;
      ace_list.push(ace);
    }
    Ok(Self(ace_list))
  }

  pub fn has_object_permission<'a, E>(&'a self, object_type: &Uuid, mut does_identify: impl FnMut(&'a SID) -> Result<bool, E>) -> Result<bool, E>
  {
    let mut result = false;
    for ace in &self.0
    {
      result = match &ace.ace_type
      {
        ACEType::AccessAllowedObject(access_object) if access_object.is_object_type(object_type) => does_identify(&access_object.subject)?,
        ACEType::AccessDeniedObject(access_object) if access_object.is_object_type(object_type) => !does_identify(&access_object.subject)?,
        _ => result
      }
    }
    Ok(result)
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ACEType
{
  AccessAllowed,
  AccessDenied,
  SystemAudit,
  SystemAlarm,
  AccessAllowedCompound,
  AccessAllowedObject(AccessObject),
  AccessDeniedObject(AccessObject),
  SystemAuditObject,
  SystemAlarmObject,
  AccessAllowedCallback,
  AccessDeniedCallback,
  AccessAllowedCallbackObject,
  AccessDeniedCallbackObject,
  SystemAuditCallback,
  SystemAlarmCallback,
  SystemAuditCallbackObject,
  SystemAlarmCallbackObject,
  SystemMandatoryLabel,
  SystemResourceAttribute,
  SystemScopedPolicyId
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ACE
{
  pub ace_type: ACEType,
  pub flags: ACEFlags,
  size: u16
}

impl ACE
{
  fn parse_ace_type(input: u8, remaining: &[u8]) -> Result<ACEType, SDDLError>
  {
    match input
    {
      0x00 => Ok(ACEType::AccessAllowed),
      0x01 => Ok(ACEType::AccessDenied),
      0x02 => Ok(ACEType::SystemAudit),
      0x03 => Ok(ACEType::SystemAlarm),
      0x04 => Ok(ACEType::AccessAllowedCompound),
      0x05 => Ok(ACEType::AccessAllowedObject(AccessObject::new(remaining)?)),
      0x06 => Ok(ACEType::AccessDeniedObject(AccessObject::new(remaining)?)),
      0x07 => Ok(ACEType::SystemAuditObject),
      0x08 => Ok(ACEType::SystemAlarmObject),
      0x09 => Ok(ACEType::AccessAllowedCallback),
      0x0A => Ok(ACEType::AccessDeniedCallback),
      0x0B => Ok(ACEType::AccessAllowedCallbackObject),
      0x0C => Ok(ACEType::AccessDeniedCallbackObject),
      0x0D => Ok(ACEType::SystemAuditCallback),
      0x0E => Ok(ACEType::SystemAlarmCallback),
      0x0F => Ok(ACEType::SystemAuditCallbackObject),
      0x10 => Ok(ACEType::SystemAlarmCallbackObject),
      0x11 => Ok(ACEType::SystemMandatoryLabel),
      0x12 => Ok(ACEType::SystemResourceAttribute),
      0x13 => Ok(ACEType::SystemScopedPolicyId),
      ace_type => Err(SDDLError::InvalidACEType(ace_type))
    }
  }

  fn new(input: &[u8]) -> Result<Self, SDDLError>
  {
    let size = le_field_u16(input, "ace_size", 2)?;
    Ok(Self
    {
      ace_type: Self::parse_ace_type(field_u8(input, "ace_type", 0)?, field_subslice(input, "ace_contents", 4)?)?,
      flags: ACEFlags::field(input, 1)?,
      size
    })
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct SDDL
{
  pub control: ControlFlags,
  pub owner: SID,
  pub group: SID,
  pub sacl: Option<ACL>,
  pub dacl: Option<ACL>
}

impl SDDL
{
  pub fn new(input: &[u8]) -> Result<Self, SDDLError>
  {
    check_revision(field_u8(input, "revision", 0)?, 1)?;
    let control = ControlFlags::field(input, 2)?;
    if !control.contains(ControlFlags::SELF_RELATIVE) { return Err(SDDLError::NotSelfRelative) }
    let sacl_offset = le_field_u32(input, "sacl_offset", 12)? as usize;
    let dacl_offset = le_field_u32(input, "dacl_offset", 16)? as usize;
    let owner_offset = le_field_u32(input, "owner_offset", 4)? as usize;
    let group_offset = le_field_u32(input, "group_offset", 8)? as usize;
    Ok(Self
    {
      control,
      owner: SID::new(field_subslice(input, "owner_offset", owner_offset)?)?,
      group: SID::new(field_subslice(input, "group_offset", group_offset)?)?,
      sacl: if sacl_offset == 0 { None } else { Some(ACL::new(field_subslice(input, "sacl_offset", sacl_offset)?)?) },
      dacl: if dacl_offset == 0 { None } else { Some(ACL::new(field_subslice(input, "dacl_offset", dacl_offset)?)?) }
    })
  }
}

pub const ENROLL: Uuid = uuid!("0e10c968-78fb-11d2-90d4-00c04f79dc55");
pub const AUTO_ENROLL: Uuid = uuid!("a05b8cc2-17bc-4802-a710-e7c15ab866a2");