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

#![allow(dead_code)]

// These parameters were issued by the gen_params.sage script
// They aim to be similar to the implementation linked in the original paper
// https://extgit.iaik.tugraz.at/krypto/zkfriendlyhashzoo/-/blob/master/plain_impls/src/griffin/griffin_params.rs
// The seeding of Shake isn't cleary defined (unlike RescuePrime, for example)
// There is a test in the main that generated the curves characteristics

pub const R: usize = 1;
pub const M: usize = 3; // The sponge state size
pub const N: usize = 12; // The number of rounds
pub const NB_CONSTS: usize = M * (N - 1); // The number of constants
pub const ALPHA: [u64; 4] = [
    0xc86a_d9c2_50e9_ba5e,
    0x3ed6_ec22_7ea7_8169,
    0xd82e_c6ff_27d4_1eac,
    0x00d5_60c0_b02f_92c0,
];
pub const BETA: [u64; 4] = [
    0x6157_5f6a_c44b_3604,
    0xe13e_1eae_0579_5c4a,
    0x48ea_db43_5111_8633,
    0x1635_81d4_d39d_f303,
];

// Values of alpha and it's inverse on both the fields
pub const D_BLS381: [u64; 4] = [
    0x0000_0000_0000_0005,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
];
pub const D_INV_BLS381: [u64; 4] = [
    0x3333_3332_cccc_cccd,
    0x217f_0e67_9998_f199,
    0xe14a_5669_9d73_f002,
    0x2e5f_0fba_dd72_321c,
];

pub const ROUND_CONSTANTS: [[u64; 4]; NB_CONSTS] = [
    [
        0x39de_9523_ad2b_9b8c,
        0xed6c_9bb3_a0cb_c656,
        0xc804_428b_7330_dcea,
        0x33c9_b186_ec5c_99fd,
    ],
    [
        0x67af_54bd_55ef_3a40,
        0x50e5_4da1_64c1_5fcd,
        0xddd8_64c1_a1e2_f3ff,
        0x1ee4_91ca_6d21_4fc1,
    ],
    [
        0x202a_e723_0483_da1d,
        0x51ae_c912_c9bf_e490,
        0x9b1b_d0f3_10e5_4ebf,
        0x4c1b_a4f9_3409_12ab,
    ],
    [
        0xdfe0_ec8b_dc41_be53,
        0x02b5_9fe4_8cff_f2ad,
        0xd1de_4a46_fe46_e06b,
        0x33aa_8219_9f04_c44a,
    ],
    [
        0xfcf8_0a6e_598d_9191,
        0xfe30_5034_36fc_8263,
        0xce85_e28b_b94b_1603,
        0x3270_dc02_8275_0da2,
    ],
    [
        0xebb0_56d3_743d_c41f,
        0xe63a_1377_d5c5_7831,
        0x2000_c133_9886_ff1e,
        0x15fe_db66_10d6_07e3,
    ],
    [
        0x27c2_c9d9_594e_0a2c,
        0x6888_b7ee_9def_ce8e,
        0x2a75_a2c9_267b_c5ca,
        0x0067_e674_c5b6_eb85,
    ],
    [
        0x161a_05ef_dc78_7597,
        0x34dc_3e01_47a5_aeba,
        0xf6c6_fb2b_d7d0_3ed0,
        0x0822_c0ce_6648_91d2,
    ],
    [
        0x16e6_565e_9e26_a437,
        0xb648_94c1_9ce1_2597,
        0x0e31_e50d_88fa_7594,
        0x415f_ec66_e44f_1fc2,
    ],
    [
        0x2cc0_41a6_cd0c_fa7d,
        0x56b3_455f_e9a2_3b93,
        0x2b0a_af30_15c9_d308,
        0x3b77_9718_395b_bc6b,
    ],
    [
        0xf5e8_b2fb_32a8_36d8,
        0xc9d7_dc20_d8a3_e74d,
        0x6116_4f84_be5b_b1bc,
        0x5554_f0af_d180_f658,
    ],
    [
        0x15c3_f6a6_ad89_877f,
        0x8943_2316_0692_008e,
        0x2028_6b02_0c2c_9e7e,
        0x0cb3_2d52_7b14_feef,
    ],
    [
        0xeef2_0917_ba88_b34b,
        0xde35_19f5_63c0_d3bf,
        0x3b76_3395_3ae1_0266,
        0x1bfd_1cf8_0505_b8c2,
    ],
    [
        0x4700_8cc0_5fc9_1534,
        0xe67c_f484_5a3c_ef6b,
        0x11dd_3b52_4629_94a7,
        0x2d67_5120_2bc4_3322,
    ],
    [
        0x0043_c275_2994_6067,
        0x3ede_25f7_9faa_5c25,
        0x832b_6909_bcb6_5c90,
        0x4d67_e460_2a5d_1143,
    ],
    [
        0x36f2_83ca_f985_54c7,
        0x037f_3bf9_beb9_29c4,
        0x03a8_4c58_b69d_1458,
        0x6e58_4505_cda4_d1ff,
    ],
    [
        0x47a0_2b1b_3764_50dc,
        0x9d04_053d_8c0c_25ed,
        0x3835_20f4_cb68_32a5,
        0x6155_4337_70db_3f7c,
    ],
    [
        0x490a_9ce8_51f1_3d39,
        0x581c_2b90_499e_4821,
        0xc4a3_22fd_b97f_893c,
        0x6aee_4021_c3b8_5098,
    ],
    [
        0x6c8e_e0f6_8f3a_a725,
        0x4bbf_ade5_d933_29e9,
        0x7ac2_af7e_f1f2_1ce0,
        0x63ea_b345_7edb_14df,
    ],
    [
        0x90e4_d4a7_9fe6_27f8,
        0x0fdf_c99c_e71d_905e,
        0x43cd_e042_1ef8_56da,
        0x6315_7169_c7b7_4721,
    ],
    [
        0x99f9_b39a_cfd5_7173,
        0xc735_2272_e2b4_aca0,
        0xa698_7d1c_feca_b276,
        0x6548_5ceb_49f7_96ec,
    ],
    [
        0x2074_d5d2_ee8c_3eff,
        0x820e_9dad_d3d6_67e0,
        0x45de_5891_ab02_e857,
        0x6162_dabc_fd6f_c28d,
    ],
    [
        0x713b_5410_ae35_6409,
        0x07eb_7c7d_e9bf_4988,
        0x5316_0203_2d24_9a5a,
        0x6faa_20f3_4487_0680,
    ],
    [
        0x1e6c_2aed_ea13_6080,
        0x07fa_b6f8_58ca_255e,
        0x63fc_8356_eaa2_1ee1,
        0x7294_33e7_d6d1_e133,
    ],
    [
        0xbeed_be8d_89cd_1e83,
        0xabaa_d280_620e_117e,
        0x2e4d_a057_8cbf_0905,
        0x4881_eefa_4423_4624,
    ],
    [
        0xfbf8_925e_2109_4006,
        0x34f0_7e78_097f_6bf2,
        0xd1e7_bd9b_3f21_6395,
        0x5bc4_dd08_c087_040c,
    ],
    [
        0x10e0_f6b7_e522_4983,
        0x3186_8bac_d28d_85c4,
        0x6117_1a9e_7bd2_e03a,
        0x32e1_2237_e567_b29d,
    ],
    [
        0xef37_4361_c8db_baf0,
        0x38b1_332d_187d_96df,
        0x682d_8517_c8ac_a0d2,
        0x49c7_6440_c2fb_b8fa,
    ],
    [
        0xc26f_24ef_34c9_2ecc,
        0xa0fd_30ba_0224_1015,
        0x160e_d766_168f_188a,
        0x4567_c1e7_6236_b51e,
    ],
    [
        0x66b3_f3f3_37d0_3791,
        0xe27d_72c5_07b0_d6dd,
        0xf91e_3984_8aae_0c7c,
        0x1049_c524_5292_44ec,
    ],
    [
        0xb62a_d182_8e23_4617,
        0x2c5a_bbb6_3ef2_2643,
        0x4140_09eb_4e89_a843,
        0x4b45_fd75_3b33_8337,
    ],
    [
        0x741b_0e07_6bad_18fe,
        0x610e_833e_cdf4_1b64,
        0x454b_d1e1_e2d9_5dbb,
        0x0ae1_8194_93b8_4236,
    ],
    [
        0x9179_1bb6_1076_3ce1,
        0x59f5_08bc_5dfb_92b9,
        0x93d6_ade2_6d63_9d3d,
        0x6918_4051_c892_2f7c,
    ],
];
