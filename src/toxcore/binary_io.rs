/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Functions for binary IO.

use nom::IResult;
use num_traits::identities::Zero;

/// Serialization into bytes.
pub trait ToBytes {
    /// Serialize into bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Result type for parsing methods
pub type ParseResult<'a, Output> = IResult<&'a [u8], Output>;

/// De-serialization from bytes.
pub trait FromBytes: Sized {
    /// De-serialize from bytes.
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self>;

    /// De-serialize from bytes, or return `None` if de-serialization failed.
    /// Note: `Some` is returned even if there are remaining bytes left.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match Self::parse_bytes(bytes) {
            IResult::Done(_, value) => Some(value),
            IResult::Error(err) => {
                error!("Can't parse bytes. Error: {:?}", err);
                None
            },
            IResult::Incomplete(_) => None
        }
    }
}

macro_rules! from_bytes (
    ($name:ident, $submac:ident!( $($args:tt)* )) => (
        impl FromBytes for $name {
            named!(parse_bytes<&[u8], Self>, $submac!($($args)*));
        }
    );
);


/// Append `0`s to given bytes up to `len`. Panics if `len` is smaller than
/// padded `Vec`.
pub fn append_zeros<T: Clone + Zero>(v: &mut Vec<T>, len: usize) {
    let l = v.len();
    v.append(&mut vec![T::zero(); len - l]);
}


/** Calculate XOR checksum for 2 [u8; 2].

    Used for calculating checksum of ToxId.

    https://zetok.github.io/tox-spec/#tox-id , 4th paragraph.
*/
pub fn xor_checksum(lhs: &[u8; 2], rhs: &[u8; 2]) -> [u8; 2] {
    [lhs[0] ^ rhs[0], lhs[1] ^ rhs[1]]
}
