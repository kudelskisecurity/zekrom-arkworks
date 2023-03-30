/* zekrom-arkworks
* Copyright (C) 2023
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Mostly based on "SAFE (Sponge API for Field Elements) – A Toolbox for ZK Hash Applications" - https://hackmd.io/bHgsH6mMStCVibM_wYvb2w
//! Code inspiration by the reference implementation : https://github.com/filecoin-project/neptune/tree/master/src/sponge

use crate::common::pattern::*;

/// This trait define the API from [SAFE (Sponge API for Field Elements)](https://hackmd.io/bHgsH6mMStCVibM_wYvb2w)
/// It implements the core 4 functions *start*, *absorb*, *squeeze* and *finish*
pub trait SpongeAPI {
    type Value;

    fn start(&mut self, pattern: IOPattern, domain_separator: Option<u32>);
    fn absorb(&mut self, length: u32, elements: &[Self::Value]);
    fn squeeze(&mut self, length: u32) -> Vec<Self::Value>;
    fn finish(&mut self) -> Result<(), anyhow::Error>;
}

/// This trait defines the necessary functions inside a chip implementation.
/// It allows the SpongeAPI to use the chip transparently, and leaves the
/// details of each construction to the developer.
pub trait ChipAPI {
    type Value;

    /// This method initializes the state of the chip
    ///
    /// It can take a tag to initialize the capacity with a value x
    /// It can also be called with 0 to reset the state to an array of M 0s
    fn init(&mut self, tag: u128) -> Result<(), anyhow::Error>;

    fn read(&mut self) -> Self::Value;

    fn add(&mut self, val: &Self::Value) -> Result<(), anyhow::Error>;

    fn permutation(&mut self) -> Result<(), anyhow::Error>;
}

/// This struct defines the basics of a sponge
///
/// The chip depends on the primitives / libraries used, but the sponge remains the same
#[derive(Clone)]
pub struct Sponge<C: ChipAPI> {
    pub chip: C,
    pub rate: usize,
    pub absord_pos: usize,
    pub squeeze_pos: usize,
    pub op_count: usize,
    pub pattern: IOPattern,
}

/// This trait defines an interface between the sponge and the chip.
///
/// This chip implements very basic operations such as permutation or adding to the rate.
/// This allows to expose some properties (rate, absorb_pos, etc...) and logic to the sponge.
/// These functions are only called via SpongeAPI and shouldn't be reimplemented, they can be extended if needed
pub trait InnerSpongeAPI {
    type Value;

    // Methods based on the paper recommendation
    fn initialize_capacity(&mut self, tag: u128);
    fn read_rate_element(&mut self, offset: usize) -> Self::Value;
    fn permute(&mut self);

    // Some additions based on the reference implementation
    fn rate(&self) -> usize;
    fn absorb_pos(&self) -> usize;
    fn squeeze_pos(&self) -> usize;
    fn set_absorb_pos(&mut self, pos: usize);
    fn set_squeeze_pos(&mut self, pos: usize);
    fn pattern(&self) -> &IOPattern;
    fn set_pattern(&mut self, pattern: IOPattern);

    fn increment_io_count(&mut self) -> usize;

    fn add_element_to_rate_at(&mut self, offset: usize, x: &Self::Value);
}

impl<C: ChipAPI> InnerSpongeAPI for Sponge<C> {
    type Value = C::Value;

    /// Call the init function of a chip, provides the tag
    fn initialize_capacity(&mut self, tag: u128) {
        let res = self.chip.init(tag);
        // println!("{:?}", res);
        assert!(res.is_ok(), "init failed") // todo : clean this
    }

    /// Read the rate at said offset
    fn read_rate_element(&mut self, offset: usize) -> Self::Value {
        assert!(offset < self.rate, "Offset outside of rate!");
        self.chip.read()
    }

    /// Ask the chip to permute its internal state
    fn permute(&mut self) {
        let res = self.chip.permutation();
        if res.is_err() {
            println!("{:?}", res);
        }
        assert!(res.is_ok(), "The permutation didn't complete correctly")
    }

    fn rate(&self) -> usize {
        self.rate
    }

    fn absorb_pos(&self) -> usize {
        self.absord_pos
    }

    fn squeeze_pos(&self) -> usize {
        self.squeeze_pos
    }

    fn set_absorb_pos(&mut self, pos: usize) {
        self.absord_pos = pos
    }

    fn set_squeeze_pos(&mut self, pos: usize) {
        self.squeeze_pos = pos
    }

    fn pattern(&self) -> &IOPattern {
        &self.pattern
    }

    fn set_pattern(&mut self, pattern: IOPattern) {
        self.pattern = pattern
    }

    /// Increments the count and return the past count
    fn increment_io_count(&mut self) -> usize {
        self.op_count += 1;
        self.op_count - 1
    }

    /// Ask the chip to add an element to the rate at the specified offset
    fn add_element_to_rate_at(&mut self, offset: usize, x: &Self::Value) {
        assert_eq!(offset, 0, "Offset outside of rate!");
        let res = self.chip.add(x);
        assert!(res.is_ok(), "Add failed"); // todo : clean
    }
}

impl<S: InnerSpongeAPI> SpongeAPI for S {
    type Value = S::Value;

    /// This should be called before any other function on a sponge.
    ///
    /// It calculates the tag, initialises the state and the internal values
    fn start(&mut self, pattern: IOPattern, domain_separator: Option<u32>) {
        let tag = pattern.get_tag(domain_separator);

        self.set_pattern(pattern);
        self.initialize_capacity(tag);

        self.set_absorb_pos(0);
        self.set_squeeze_pos(0);
    }

    /// This function allows to feed field elements to the sponge
    ///
    /// It's necessary to specify how many are given, and to respect the IOPattern
    fn absorb(&mut self, length: u32, elements: &[Self::Value]) {
        assert_eq!(length as usize, elements.len());

        let rate = self.rate();

        for element in elements.iter() {
            if self.absorb_pos() == rate {
                self.permute();
                self.set_absorb_pos(0);
            }
            self.add_element_to_rate_at(self.absorb_pos(), element);
            self.set_absorb_pos(self.absorb_pos() + 1);
        }
        let op = SpongeOp::Absorb(length);
        let old_count = self.increment_io_count();
        assert_eq!(Some(&op), self.pattern().op_at(old_count));

        self.set_squeeze_pos(rate);
    }

    /// This function allows us to read elements from the rate
    fn squeeze(&mut self, length: u32) -> Vec<Self::Value> {
        let rate = self.rate();

        let mut out = Vec::with_capacity(length as usize);

        for _ in 0..length {
            if self.squeeze_pos() == rate {
                self.permute();
                self.set_squeeze_pos(0);
                self.set_absorb_pos(0);
            }
            out.push(self.read_rate_element(self.squeeze_pos()));
            self.set_squeeze_pos(self.squeeze_pos() + 1);
        }
        let op = SpongeOp::Squeeze(length);
        let old_count = self.increment_io_count();
        assert_eq!(Some(&op), self.pattern().op_at(old_count));

        out
    }

    /// This function concludes the lifetime of a sponge
    ///
    /// It will reset the internal state, (todo) attempt to erase it from memory
    /// and assert that the correct number of calls were made.
    fn finish(&mut self) -> Result<(), anyhow::Error> {
        self.initialize_capacity(0);
        let final_io_count = self.increment_io_count();
        if final_io_count == self.pattern().len() {
            Ok(())
        } else {
            Err(anyhow::Error::msg("IOPattern missmatch"))
        }
    }
}
