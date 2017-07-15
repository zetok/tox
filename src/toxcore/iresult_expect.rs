/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Evgeny Kurnevsky <kurnevsky@gmail.com>

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

//! Expect method for IResult.

use nom::IResult;

/// Adds an expect method.
pub trait Expect<T> {
    /// Unwraps a result, yielding the content.
    ///
    /// # Panics
    ///
    /// Panics if the value is an error, with a passed panic message.
    fn expect(self, &str) -> T;
}

impl<I, O> Expect<(I, O)> for IResult<I, O> {
    fn expect(self, err: &str) -> (I, O) {
        match self {
            IResult::Done(i, o) => (i, o),
            IResult::Incomplete(_) => panic!("Incomplete: {}", err),
            IResult::Error(e) => panic!("{}: {}", e.description(), err)
        }
    }
}
