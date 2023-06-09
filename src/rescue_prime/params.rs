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

pub(crate) const R: usize = 1;
pub(crate) const M: usize = 3; // The sponge state size
pub(crate) const MDS_SIZE: usize = M * M; // The Matrix size
pub(crate) const N: usize = 14; // The number of rounds
pub(crate) const NB_CONSTS: usize = 2 * M * N; // The number of constants

// Values of alpha and it's inverse on both the fields
pub const ALPHA_BLS381: [u64; 4] = [
    0x0000_0000_0000_0005,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
];
pub const ALPHAINV_BLS381: [u64; 4] = [
    0x3333_3332_cccc_cccd,
    0x217f_0e67_9998_f199,
    0xe14a_5669_9d73_f002,
    0x2e5f_0fba_dd72_321c,
];

pub const MDS: [[u64; 4]; MDS_SIZE] = [
    [
        0x0000_0000_0000_0157,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ],
    [
        0xffff_fffe_ffff_fe72,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ],
    [
        0x0000_0000_0000_0039,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ],
    [
        0x0000_0000_0000_4c5f,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ],
    [
        0xffff_fffe_ffff_a881,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ],
    [
        0x0000_0000_0000_0b22,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ],
    [
        0x0000_0000_000e_ea8e,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ],
    [
        0xffff_fffe_ffee_f262,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ],
    [
        0x0000_0000_0002_2312,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ],
];

pub const ROUND_CONSTANTS: [[u64; 4]; NB_CONSTS] = [
    [
        0xd9af_cbe5_b354_15c8,
        0x8baa_b73d_8be8_19a7,
        0x0a12_1a70_c13f_5e68,
        0x3489_b290_80b3_0120,
    ],
    [
        0xbec6_5e1a_7fb4_800e,
        0x4bf7_59d6_03ba_fb29,
        0x5854_04f3_3240_ec38,
        0x5feb_371f_cdcc_06b4,
    ],
    [
        0x9eef_3b3c_ffd3_f394,
        0x9b51_1ae7_c5ea_5ae7,
        0x5f20_8018_2051_d29f,
        0x716b_03f2_ea78_1566,
    ],
    [
        0xbb21_df5f_4ec0_760b,
        0xb28d_f9cb_4844_cc72,
        0xe617_85ee_25e6_6f83,
        0x65a0_712c_c79f_9df5,
    ],
    [
        0x0551_6419_b6cc_5bbc,
        0x1b24_78be_b58c_45ae,
        0xec2c_e82b_89fb_ec14,
        0x1c25_cd31_7b42_85cd,
    ],
    [
        0x4ba4_32e1_f04d_76d1,
        0x58c4_8c91_0337_e2bf,
        0x9da6_9c24_32e8_1dcd,
        0x5eb6_5006_6df7_8d85,
    ],
    [
        0xe9e9_4649_1745_065c,
        0x9ee8_2af6_eb77_2b76,
        0xc056_f1d5_2362_fba6,
        0x3826_effb_b8ed_39fc,
    ],
    [
        0x4047_814b_4355_f75b,
        0xae2d_54f3_029f_c872,
        0x28cf_43d6_ea98_331e,
        0x1511_89b7_c5d7_19aa,
    ],
    [
        0xb2d6_65e2_583f_bdff,
        0x920f_e5f8_80d8_c6fb,
        0x0151_5912_9fde_d162,
        0x4333_df3c_236f_5400,
    ],
    [
        0xbf3c_a4fe_0b33_07aa,
        0x4727_b9ac_74c9_bbda,
        0x12a8_414b_4f9a_a834,
        0x22f4_48b3_d6b9_dcfa,
    ],
    [
        0x7991_47e3_f585_d27e,
        0xdf3a_ee0a_49e1_f1ce,
        0xeac4_c36b_acfc_954f,
        0x559f_8473_8e40_6207,
    ],
    [
        0x5771_fa73_46bf_dc4e,
        0xac24_4fe9_60bf_bd75,
        0xb0a1_e0d1_8ec7_16ff,
        0x637f_691c_42ef_9df7,
    ],
    [
        0x4000_fc67_4637_969c,
        0xe3d6_99a8_35a8_3f78,
        0xe0ea_d424_bfb1_cb7e,
        0x502c_3d50_c58f_41fd,
    ],
    [
        0x79b9_04e1_938b_6706,
        0xe9a7_a137_fb8a_e6a4,
        0xc248_ae6f_2512_d186,
        0x0303_8d79_7b07_5c99,
    ],
    [
        0x470c_e666_d052_5203,
        0xdcec_4091_0c08_eb7d,
        0x3ecf_4290_c812_0347,
        0x389b_3b55_a2a5_5263,
    ],
    [
        0x471d_ad52_0c90_435e,
        0x9103_c24c_a354_fae4,
        0xe259_b85e_b360_4f2f,
        0x6587_2838_c5a5_5b6e,
    ],
    [
        0x2a8b_5c18_b513_72ef,
        0x6508_8b22_9a49_3dea,
        0x535d_778c_00b7_d157,
        0x1f94_c308_6cfc_6ef7,
    ],
    [
        0x892f_213a_6f80_226f,
        0x992c_7a28_c1ac_e8ec,
        0x634b_afc5_153d_3e9e,
        0x0d73_7a59_1858_b047,
    ],
    [
        0xf14e_d68b_bcca_8cba,
        0x44ae_6917_e721_d86f,
        0x5769_33c5_5c80_1469,
        0x135e_85bd_c270_bcb6,
    ],
    [
        0x063e_1fcc_758e_c06b,
        0xf8d0_e0be_21d7_ebc5,
        0x6215_751e_0c64_8aa4,
        0x6e72_799a_4325_693a,
    ],
    [
        0x78c6_3644_d954_7150,
        0x4c7d_8269_db4a_872a,
        0xb997_2cdf_babe_37ec,
        0x28c1_576e_ae9c_8e63,
    ],
    [
        0xcb5b_51b3_8392_099d,
        0x1903_7a66_8794_a013,
        0xcb9a_27ec_4fe7_7f54,
        0x2285_4402_e5e8_1a19,
    ],
    [
        0xde77_5291_fbf3_ef5d,
        0xb58b_ee46_ea66_292a,
        0x630a_21a6_711c_12fe,
        0x0b24_7edf_907a_6f10,
    ],
    [
        0x5129_1a2d_6223_bbe1,
        0x0274_ba7e_a4e0_2a6c,
        0x7d9b_f7f6_697d_5c2e,
        0x2b45_0229_56a7_50bf,
    ],
    [
        0x67ae_d317_45dd_1a07,
        0x27c0_1abe_93b4_c714,
        0x9836_a95a_ba16_7c2d,
        0x6193_b105_6ea0_cec3,
    ],
    [
        0xbbdd_2cf0_f173_9258,
        0x878f_41c6_aadd_0538,
        0xa41a_1b54_38ac_4128,
        0x41ea_3b26_3526_12e7,
    ],
    [
        0xd1d3_8c16_814c_b4e8,
        0x03b9_5f12_e939_dc45,
        0xcb5d_ad5b_5d46_faff,
        0x010a_5a8d_c0a2_8128,
    ],
    [
        0x7e9b_34ae_014a_d585,
        0x01ee_3433_6050_f408,
        0x16fb_ff3e_33b6_3919,
        0x27c9_5684_d202_8684,
    ],
    [
        0x6930_132d_faae_c47e,
        0xc527_b26d_1e40_579d,
        0x7497_182d_bf6d_c0ac,
        0x5b83_15f9_9933_0625,
    ],
    [
        0xd2fe_989e_a7b7_e1ce,
        0xb122_073a_771f_d0b8,
        0x40b1_0138_d72c_6a4b,
        0x21ab_b111_a999_73fd,
    ],
    [
        0xd1bc_13f9_4f49_fa6d,
        0x7004_4ecb_3456_5be3,
        0xba98_3202_981b_60d9,
        0x5c4f_f7c0_64ab_eedf,
    ],
    [
        0xb031_2f6b_4b5a_0958,
        0xea3a_4671_6f87_60b8,
        0x9b3e_dc5d_4233_53ae,
        0x5242_0f41_4468_4b9a,
    ],
    [
        0x9bbc_c2ea_b7ec_c497,
        0x0c5b_bc11_c2a5_09d3,
        0x0707_5890_3a7d_a030,
        0x0286_1172_1a9d_3fe5,
    ],
    [
        0xb979_5544_bd54_a6ec,
        0x5333_7c95_e949_6f92,
        0x2434_773d_0cb0_4b7a,
        0x183a_122b_1d51_e447,
    ],
    [
        0x3167_df0b_40b9_924e,
        0x6765_c99f_e41d_c807,
        0x6894_8745_3b08_1044,
        0x28a0_279c_4be9_0e86,
    ],
    [
        0xe7fb_0c7e_6cc6_ee81,
        0x830c_d4d2_5bda_f519,
        0x33ef_79a7_ade5_670d,
        0x3331_b6ae_d1b3_0391,
    ],
    [
        0x25c3_fb1a_9470_7b9f,
        0xe487_2220_c32a_45b2,
        0x4e47_a120_0963_560b,
        0x6f29_4958_6004_9eda,
    ],
    [
        0xe3d2_6fad_fe77_5adb,
        0x2992_2df2_eead_31ab,
        0x290a_e459_c17f_d9a5,
        0x57b4_c9b2_4f07_556f,
    ],
    [
        0xb5e3_f71a_1ed2_124a,
        0x1b85_e015_7d2c_8cd1,
        0x752e_f4e2_1eca_6bf5,
        0x2183_ac73_53b4_2ea4,
    ],
    [
        0x2e52_2596_c41f_732d,
        0xfe32_f6ea_c064_c0c6,
        0x7005_1ae6_7091_a2aa,
        0x70e4_88cb_f07a_7086,
    ],
    [
        0x988b_f871_bbbb_3617,
        0xc87e_10d4_2b85_5475,
        0xa2a7_5e58_1bde_5fa0,
        0x44e1_8861_ff99_d91d,
    ],
    [
        0xc78f_6f86_0288_5a19,
        0xc565_e12c_04df_83ac,
        0xa668_01ca_d4e4_4db6,
        0x0b03_6f3f_4700_c598,
    ],
    [
        0x750d_18ad_278a_31cb,
        0x9fcb_c0e7_d06c_8116,
        0xb295_225a_b74d_8f9f,
        0x3c30_fc92_d23c_89e1,
    ],
    [
        0x488b_7790_fdd6_5892,
        0x2abd_30bc_0aef_4797,
        0x14ba_aec1_8076_9169,
        0x29f5_78da_86ed_40e7,
    ],
    [
        0x0b3d_6e64_3f2f_274c,
        0x53a3_fd8c_c146_4382,
        0xc74e_56aa_653a_1bc6,
        0x31f4_dbbe_e474_49b4,
    ],
    [
        0xdb5b_f6f2_0a9f_ceb0,
        0x3e24_3c76_e419_9aa7,
        0x182f_72c0_b80f_93d1,
        0x01f2_57e7_1864_1970,
    ],
    [
        0x6da2_1e4b_4141_a589,
        0xef07_c6a8_1482_ff9f,
        0x2498_cd63_742d_50d5,
        0x0a88_d269_1b84_c43d,
    ],
    [
        0x7a02_4598_6694_e0c5,
        0x5b74_0daf_d021_13a8,
        0x6456_afc7_f955_a1e1,
        0x1797_7ce6_368d_2bad,
    ],
    [
        0x91e9_e314_77c0_e7ca,
        0x8b22_32c0_d0b3_7151,
        0xe264_0da7_1365_8761,
        0x5f12_b703_6caa_0391,
    ],
    [
        0xd9f5_113c_bfe9_5a35,
        0xba04_d897_1977_286e,
        0xd117_dfe6_cba1_62ec,
        0x6075_c000_057c_9412,
    ],
    [
        0x62fd_ff15_4cea_e0c4,
        0xf2e7_ba2f_e1e7_aaad,
        0x9c70_cf81_9a32_e8c9,
        0x5ca2_8635_5c34_b3c8,
    ],
    [
        0xd511_c98c_a40a_c003,
        0x7112_a51a_4cd5_88b2,
        0x0245_45af_1d68_345e,
        0x4e24_e7ad_bc89_a605,
    ],
    [
        0xd42a_512a_32b2_ed13,
        0x7193_87a5_910c_9fcd,
        0x9d15_5dac_f1c7_07e6,
        0x1ee7_8b62_7d15_e497,
    ],
    [
        0xac60_325a_7720_4127,
        0x380f_6335_4b6d_0ab7,
        0xacfe_de6a_9d23_2658,
        0x5b6e_ef92_8c44_8b4b,
    ],
    [
        0x3340_d456_1674_00eb,
        0xd48d_1ee7_334e_2c16,
        0xe1a8_f2ab_8a7b_9bf4,
        0x44b3_ff6b_a72c_734d,
    ],
    [
        0x64f4_4322_93e4_2eaa,
        0x6f75_872d_dc7f_2a10,
        0x1f16_664f_5255_84d2,
        0x22c8_911d_b6c2_6456,
    ],
    [
        0x76c5_2e07_ab13_17ea,
        0xb780_817b_e14e_d147,
        0x6a7f_f9b1_0791_6555,
        0x6ab6_9e10_a275_fbbf,
    ],
    [
        0xa1e6_8347_5647_79a1,
        0xcc58_ff63_9485_d677,
        0x98f8_af6a_98b0_6387,
        0x5cdd_1c0c_2016_e406,
    ],
    [
        0x2de7_1ddb_d5cf_736a,
        0x873e_e0f8_9f7b_197e,
        0x93ee_fbd3_6f42_f658,
        0x3bf0_9603_17fc_57b6,
    ],
    [
        0x22c2_96d5_453e_1eef,
        0x3e60_f7b2_8b1b_5a91,
        0x42b3_3162_a955_88c3,
        0x187a_c145_54d6_7082,
    ],
    [
        0xe1f9_dec4_c993_0a2d,
        0xc765_dccc_9aa6_451a,
        0x6e0e_bc41_676b_07db,
        0x1537_c930_6ae1_3f52,
    ],
    [
        0xe272_6484_d430_0f56,
        0xa25f_5488_3330_e310,
        0x21a4_80d4_dd42_1b90,
        0x7132_cf1b_4a82_936d,
    ],
    [
        0xc79a_d1ea_4bb4_7771,
        0x40f7_5656_0e73_734d,
        0x1679_b819_9d24_aaba,
        0x4c48_1aee_c6d7_33a0,
    ],
    [
        0x7895_9ff6_bc2c_182c,
        0xb817_d234_a6e2_9030,
        0x5069_8dfe_8d73_a031,
        0x0e8e_005a_336d_fff8,
    ],
    [
        0x2e23_a778_e272_cab0,
        0x6d59_08a1_0547_c0b9,
        0x2295_62b2_b261_63a8,
        0x38b7_1c52_04ad_8b42,
    ],
    [
        0x9965_f8db_e1a3_72d0,
        0xe282_edfa_b9c1_3ccb,
        0xceb7_c2b8_0aa6_b648,
        0x32a9_cfde_d738_07f0,
    ],
    [
        0x2c1c_6de5_afe2_a1af,
        0x9977_167f_ceaf_d55b,
        0x4b52_e6c5_ca52_389e,
        0x49d0_7e87_c893_7014,
    ],
    [
        0x2752_7e43_506b_1fa8,
        0x3309_b151_2d04_cb66,
        0x51fa_2d2e_1d13_cf32,
        0x45b0_0439_4a9c_20ad,
    ],
    [
        0xb5b0_eab2_ed5b_8d1c,
        0x1ef9_1b5f_b4b4_96f7,
        0x7486_9fdf_08a1_95d4,
        0x4a3f_60a2_3a33_561f,
    ],
    [
        0x2608_0a5c_432b_a425,
        0xc8a3_d1f9_1374_7669,
        0x39c3_47bc_f4a6_475b,
        0x090e_9806_671e_290e,
    ],
    [
        0x5ee6_8cb9_cab6_7882,
        0x219a_7e5e_9671_7834,
        0x72e9_a618_b101_cbe2,
        0x20e4_b45a_0196_8d8d,
    ],
    [
        0x611d_5108_56a3_8e76,
        0x7135_4dcc_aea7_b557,
        0x8077_019e_73c8_ea79,
        0x4968_93cd_586c_8bc6,
    ],
    [
        0x27e9_47b0_3335_893b,
        0x0627_1e9e_8dec_ac45,
        0xf9a0_c5df_8ae6_e72c,
        0x67ec_c99e_6467_af1c,
    ],
    [
        0x68c8_b32b_b780_bc42,
        0x056f_7550_a7cd_d64b,
        0x893f_ef0d_d104_5b25,
        0x5435_a7c4_ad62_08c9,
    ],
    [
        0x596a_2a4b_3fbc_807d,
        0x317c_d116_39fb_3275,
        0xbf0d_931f_030c_c1fa,
        0x500d_b249_14be_a6f7,
    ],
    [
        0xc846_ca01_0226_a935,
        0xb5bd_fd89_fdfd_2c91,
        0xbcaf_138d_b697_18d5,
        0x168f_6542_2bb8_94a4,
    ],
    [
        0x7313_8d99_ac2f_3f21,
        0x2837_76d1_b99e_d635,
        0x6b80_8d16_345c_e09a,
        0x1a29_fc6a_3dca_39ca,
    ],
    [
        0xb608_9f33_d6f7_daab,
        0xe366_9d26_2807_3f60,
        0xa7a3_8c91_f555_0526,
        0x0060_568b_ed40_1f78,
    ],
    [
        0x75fa_cba4_9ba0_5fb0,
        0xa7b4_da7c_32b6_6147,
        0x8d7d_4031_f22f_df5a,
        0x19d9_d9d0_22d3_3119,
    ],
    [
        0x3bbc_3732_e5f2_71f4,
        0xf933_c941_c826_9dbb,
        0xceaa_9f1f_beb9_2f47,
        0x2c48_388e_cd60_da7a,
    ],
    [
        0xedc1_96cb_29ed_5c3d,
        0x32b5_4364_925e_4d4d,
        0x567c_db47_9db1_15d3,
        0x3567_a502_4840_2ac1,
    ],
    [
        0x98d4_a494_8ffc_cc93,
        0x45ea_9f7c_4026_76a3,
        0x9ace_5acb_568c_caf8,
        0x2d41_6efd_0fa7_515e,
    ],
    [
        0x04ee_30cc_7469_389d,
        0xfa65_e145_6001_5de6,
        0xd7b9_8ea1_36d3_73fc,
        0x4103_9448_84de_4ea0,
    ],
    [
        0x5a17_223f_b25e_a3a8,
        0xec2c_353d_1853_4e99,
        0xa6f7_7f69_b8df_5352,
        0x3feb_df64_ebcf_ef21,
    ],
];
