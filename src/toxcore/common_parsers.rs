use std::mem::transmute;
use nom::{IResult, Needed};
use nom::IResult::*;

/// Recognizes an unsigned 1 byte integer (equivalent to take!(1)
#[inline]
pub fn ne_u8(i: &[u8]) -> IResult<&[u8], u8> {
  if i.len() < 1 {
    Incomplete(Needed::Size(1))
  } else {
    Done(&i[1..], i[0])
  }
}

/// Recognizes native endian unsigned 2 bytes integer
#[inline]
pub fn ne_u16(i: &[u8]) -> IResult<&[u8], u16> {
  if i.len() < 2 {
    Incomplete(Needed::Size(2))
  } else {
    let res = unsafe {
      transmute([i[0], i[1]])
    };
    Done(&i[2..], res)
  }
}

/// Recognizes native endian unsigned 4 bytes integer
#[inline]
pub fn ne_u32(i: &[u8]) -> IResult<&[u8], u32> {
  if i.len() < 4 {
    Incomplete(Needed::Size(4))
  } else {
    let res = unsafe {
      transmute([i[0], i[1], i[2], i[3]])
    };
    Done(&i[4..], res)
  }
}

/// Recognizes native endian unsigned 8 bytes integer
#[inline]
pub fn ne_u64(i: &[u8]) -> IResult<&[u8], u64> {
  if i.len() < 8 {
    Incomplete(Needed::Size(8))
  } else {
    let res = unsafe {
      transmute([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7]])
    };
    Done(&i[8..], res)
  }
}

/// Recognizes a signed 1 byte integer (equivalent to take!(1)
#[inline]
pub fn ne_i8(i:&[u8]) -> IResult<&[u8], i8> {
  map!(i, ne_u8, | x | { x as i8 })
}

/// Recognizes native endian signed 2 bytes integer
#[inline]
pub fn ne_i16(i:&[u8]) -> IResult<&[u8], i16> {
  map!(i, ne_u16, | x | { x as i16 })
}

/// Recognizes native endian signed 4 bytes integer
#[inline]
pub fn ne_i32(i:&[u8]) -> IResult<&[u8], i32> {
  map!(i, ne_u32, | x | { x as i32 })
}

/// Recognizes native endian signed 8 bytes integer
#[inline]
pub fn ne_i64(i:&[u8]) -> IResult<&[u8], i64> {
  map!(i, ne_u64, | x | { x as i64 })
}
