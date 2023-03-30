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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpongeOp {
    Absorb(u32),
    Squeeze(u32),
}

impl SpongeOp {
    pub fn count(&self) -> u32 {
        match self {
            Self::Absorb(n) => *n,
            Self::Squeeze(n) => *n,
        }
    }

    pub const fn is_absorb(&self) -> bool {
        matches!(self, Self::Absorb(_))
    }

    pub fn combine(&self, other: Self) -> Self {
        assert!(self.matches(other));

        match self {
            Self::Absorb(n) => Self::Absorb(n + other.count()),
            Self::Squeeze(n) => Self::Squeeze(n + other.count()),
        }
    }

    pub fn matches(&self, other: Self) -> bool {
        self.is_absorb() == other.is_absorb()
    }

    pub fn value(&self) -> u32 {
        match self {
            Self::Absorb(n) => {
                assert_eq!(0, n >> 31);
                n + (1 << 31)
            }
            Self::Squeeze(n) => {
                assert_eq!(0, n >> 31);
                *n
            }
        }
    }
}

// A large 128-bit prime, per https://primes.utm.edu/lists/2small/100bit.html.
const HASHER_BASE: u128 = (0 - 159) as u128;

#[derive(Clone, Copy, Debug)]
struct Hasher {
    x: u128,
    x_i: u128,
    state: u128,
    current_op: SpongeOp,
}

impl Default for Hasher {
    fn default() -> Self {
        Self {
            x: HASHER_BASE,
            x_i: 1,
            state: 0,
            current_op: SpongeOp::Absorb(0),
        }
    }
}

impl Hasher {
    pub fn new() -> Self {
        Default::default()
    }

    /// Update hasher's current op to coalesce absorb/squeeze runs.
    pub fn update_op(&mut self, op: SpongeOp) {
        if self.current_op.matches(op) {
            self.current_op = self.current_op.combine(op)
        } else {
            self.finish_op();
            self.current_op = op;
        }
    }

    fn finish_op(&mut self) {
        if self.current_op.count() == 0 {
            return;
        };
        let op_value = self.current_op.value();

        self.update(op_value);
    }

    pub fn update(&mut self, a: u32) {
        self.x_i = self.x_i.overflowing_mul(self.x).0;
        self.state = self
            .state
            .overflowing_add(self.x_i.overflowing_mul(a as u128).0)
            .0;
    }

    pub fn finalize(&mut self, domain_separator: u32) -> u128 {
        self.finish_op();
        self.update(domain_separator);
        self.state
    }
}

#[derive(Clone)]

pub struct IOPattern(Vec<SpongeOp>);

impl IOPattern {
    pub fn new(v: Vec<SpongeOp>) -> IOPattern {
        IOPattern(v)
    }

    pub fn get_tag(&self, domain_separator: Option<u32>) -> u128 {
        let mut hasher = Hasher::new();

        for op in self.0.iter() {
            hasher.update_op(*op);
        }

        hasher.finalize(domain_separator.unwrap_or(0))
    }

    pub fn op_at(&self, index: usize) -> Option<&SpongeOp> {
        self.0.get(index)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub fn gen_hash_pattern(m_len: usize, d_len: usize) -> IOPattern {
    IOPattern::new(vec![
        SpongeOp::Absorb(m_len as u32),
        SpongeOp::Squeeze(d_len as u32),
    ])
}

pub fn gen_ae_pattern(m_len: usize, k_len: usize, n_len: usize) -> IOPattern {
    let mut pattern = vec![
        SpongeOp::Absorb(k_len as u32),
        SpongeOp::Absorb(n_len as u32),
    ];
    for _i in 0..m_len {
        pattern.push(SpongeOp::Squeeze(1));
        pattern.push(SpongeOp::Absorb(1));
    }
    pattern.push(SpongeOp::Squeeze(1));

    IOPattern::new(pattern)
}
