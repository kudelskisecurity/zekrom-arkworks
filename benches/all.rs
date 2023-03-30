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

mod time;

use criterion::{criterion_group, criterion_main, Criterion};
use time::*;

criterion_group! {
    name = hash_duration_marlin;
    config = Criterion::default();
    targets = hash_duration_marlin_griffin, hash_duration_marlin_neptune, hash_duration_marlin_rescue
}

criterion_group! {
    name = ae_duration_marlin;
    config = Criterion::default();
    targets = ae_duration_marlin_ciminion, ae_duration_marlin_griffin, ae_duration_marlin_neptune
}

criterion_group! {
    name = hash_duration_groth16;
    config = Criterion::default();
    targets = hash_duration_groth16_griffin, hash_duration_groth16_neptune, hash_duration_groth16_rescue
}

criterion_group! {
    name = ae_duration_groth16;
    config = Criterion::default();
    targets = ae_duration_groth16_ciminion, ae_duration_groth16_griffin, ae_duration_groth16_neptune
}

criterion_main!(
    hash_duration_marlin,
    ae_duration_marlin,
    hash_duration_groth16,
    ae_duration_groth16
);
