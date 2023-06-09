/* Copyright (c) (2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

/*
struct cceckeygen_vector {
ccec_const_cp_t (*cp)(void);
uint32_t flags;
char *str_entropy;
char *str_x963_full_key;
int  retval;
};
*/

//==========================================================================
// Legacy
//==========================================================================
{ // 0: All zeroes
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .str_x963_full_key="04c7de9f744fee342d8b3bb5cbfbe1d5eae7b68d3eee6dc5b9f9c0cf7ce271daca63e002bc48c8be820a5f70fea39806b457590d1eb03067672920a37f46089602",
    .retval=CCEC_GENERATE_INVALID_INPUT,
},
{ // 1: one in LSBit
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="0000000000000000000000000000000000000000000000000000000000000001",
    .str_x963_full_key="049bbf06dad9ab5905e05471ce16d5222c89c2caa39f26267ac0747129885fbd441bcc7fa84de120a36755daf30a6f47e8c0d4bddc15036ed2a3447dfa7a1d3e880100000000000000000000000000000000000000000000000000000000000000",
    .retval=0,
},
{ // 2: one in MSBit
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="0100000000000000000000000000000000000000000000000000000000000000",
    .str_x963_full_key="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50000000000000000000000000000000000000000000000000000000000000001",
    .retval=0,
},
{ // 3: all FFF..FF
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    .str_x963_full_key="04f72cbd240e26c0d21b1023179586eb532c6102c49c3677cc1a3d132b9db9d31a43e4ca77e2a36621dc0dbd91bfe7a5d223250ef0cdca831ee453d93fa83408a700000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae",
    .retval=0,
},
{ // 4: sequence
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    .str_x963_full_key="044d40a45e3d517c3b6bb2971c771811700ba2640d03a1c4985eb3af405a0aee6e8f7405aa4476fb8af8b540e5ebdbd84c70874fb6181461b09d203d44d043a131efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412",
    .retval=0,
},
{ // 5: padded sequence (extra bytes are ignored)
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00",
    .str_x963_full_key="044d40a45e3d517c3b6bb2971c771811700ba2640d03a1c4985eb3af405a0aee6e8f7405aa4476fb8af8b540e5ebdbd84c70874fb6181461b09d203d44d043a131efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412",
    .retval=0,
},
{ // 6: truncated sequence (too short)
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_LEGACY,
    .str_entropy="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
    .str_x963_full_key="044d40a45e3d517c3b6bb2971c771811700ba2640d03a1c4985eb3af405a0aee6e8f7405aa4476fb8af8b540e5ebdbd84c70874fb6181461b09d203d44d043a131efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412",
    .retval=CCEC_GENERATE_NOT_ENOUGH_ENTROPY,
},
//==========================================================================
// RAW
//==========================================================================
{ // 7: All zeroes
.cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_FIPS,
    .str_entropy="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .str_x963_full_key="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50000000000000000000000000000000000000000000000000000000000000001",
    .retval=0,
},
{ // 8: one in LSBit
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_FIPS,
    .str_entropy="00000000000000000000000000000000000000000000000000000000000000000000000000000001",
    .str_x963_full_key="047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d10000000000000000000000000000000000000000000000000000000000000002",
    .retval=0,
},
{ // 9: one in MSBit
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_FIPS,
    .str_entropy="01000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .str_x963_full_key="0407e2515d7b2b737158354c14d5e18cfc823374644ad3a924fc4dfda78d47cbe6103e5e8cac2a15a5e593a648e3f111fcf573a0cffd3aa0c46b567c265275e67afffffffeff00000100431905529c01668a4c29445f278194e0bd679dac632551",
    .retval=0,
},
{ // 10: all FFF..FF
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_FIPS,
    .str_entropy="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    .str_x963_full_key="04a304c2b24d8bfb8fc0dcdd2ac0d47ae5ad279034c5418ac606bb232abf3984d74e7dfc62cd421952c2c39fe28d7147b95754cc65c875be614230f1ae5f1b45bcfffffffe00000001431905529c0166cd22159165b6faae71f756a572fc632550",
    .retval=0,
},
{ // 11: sequence
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_FIPS,
    .str_entropy="00000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdee",
    .str_x963_full_key="04471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714cdd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a8581234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    .retval=0,
},
{ // 12: truncated sequence (too short)
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_FIPS,
    .str_entropy="000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdee",
    .str_x963_full_key="04471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714cdd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a8581234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    .retval=CCEC_GENERATE_NOT_ENOUGH_ENTROPY,
},
/*
//==========================================================================
// DRBG
//==========================================================================
{ // 13: DRBG
.cp=&ccec_cp_256,
.flags=CCEC_GENKEY_DETERMINISTIC_PKA,
.str_entropy="1234567890abcdef1234567890abcdef",
.str_x963_full_key="04531c96d8e71d66cabfe8216bc318ade2288ac5b872a819915100e68f7dcad14223e61a75890bfce4c896554251560eda2e5a39eea42d82deb6000973958eaed705399eb3debb9a0df3aac34682f46fc47bfbbd9c66179923bba03de570f14717",
.retval=0,
},
{ // 14: DRBG
.cp=&ccec_cp_256,
.flags=CCEC_GENKEY_DETERMINISTIC_DRBG_1,
.str_entropy="1234567890abcdef1234567890abcdee",
.str_x963_full_key="047235470b2c604681c9b6d1d6251cb70557233200707411b8b65fa78c65f2ec75836f37a7a75863f6f176cb8b95f3f5304b677ec22fb16c4d67802624545a8aae42336708efcff6731212766e17ab8ac935136aca60cbc6b3b8c70abd910232e4",
.retval=0,
},
{ // 15: DRBG
.cp=&ccec_cp_256,
.flags=CCEC_GENKEY_DETERMINISTIC_DRBG_1,
.str_entropy="1234567890abcdef1234567890abcd",
.str_x963_full_key="047235470b2c604681c9b6d1d6251cb70557233200707411b8b65fa78c65f2ec75836f37a7a75863f6f176cb8b95f3f5304b677ec22fb16c4d67802624545a8aae42336708efcff6731212766e17ab8ac935136aca60cbc6b3b8c70abd910232e4",
.retval=CCDRBG_STATUS_PARAM_ERROR,
},
*/
//==========================================================================
// PKA
//==========================================================================
{ // 13: PKA
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_PKA,
    .str_entropy="040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
    .str_x963_full_key="042be3e708a4fa76b13e76f58ba2dc17c741cc5df9c10fa526b48a13692eb061b3059af0899ee5ed7fefd45da6728422438d0068d31a8d9a9c39f6fa81ce0db307010d7186d14146e21bb06ac5a4d8002a9836a474026db3587838ac6cb4a632ca",
    .retval=0,
},
{ // 14: PKA
    .cp=&ccec_cp_256,
    .flags=CCEC_GENKEY_DETERMINISTIC_PKA,
    .str_entropy="0a65c76b7dec376222f35eb79c44c711e95932854a40f518c2999c3b0d17ddd4c253b5b4cad0f4d0f004582b4cfa9453",
    .str_x963_full_key="0415defd95485ada5b8d90ac420dacbb48d81f8a35c5b0fe5f4d32358194caff43af689f3a28a7d30cb50bfbb3fdb84f3f811de693ab57576420800f567a40e9570005a22288b7c346fa4c60e99e8c9d43e4dc0da0d78e3ca92e939d9f1211df53",
    .retval=0,
},
//==========================================================================
// SecureBackup
//==========================================================================
{ // 15: SecureBackup
    .cp=&ccec_cp_256,
    .test_flags=ECKEYGEN_TEST_SECURE_BACKUP,
    .flags=(CCEC_GENKEY_DETERMINISTIC_SECBKP),
    .str_entropy="foofoofoo",
    .str_salt="4141414141414141",
    .iteration_nb=1024,
    .str_x963_full_key="049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a728b52ec2c7388924f45554f8cfe5a9c94921aa6551a36694f5a31588e09cd260c7cde9dff1a8ba477ae7e29f5a7feedecc6379f79a036ade1b53249c9ef9db8",
    .retval=0,
},
{ // 16: SecureBackup
    .cp=&ccec_cp_256,
    .flags=(CCEC_GENKEY_DETERMINISTIC_SECBKP),
    .str_entropy="abdd2f6268f3fdfa1ef7f8961706766f05dc7958f17ad94cb9d21c7be35e2c8f9887733279980412d767772d0ec320d01101580ad68151885c74e500612183f3ebab9ad6d7b9dd93a3c5be9be7233991909f95d08f1b70762d74341546045a83f1e6e394ff70ad17731cf54da69d9202e98ed363693ba4930e2a19ec69891a2afb09f7a2cb8e9e9e1219349d12729380e06abc100cde3faa7c5018ecb5537ddc54bc34d2ed524d72c43f0de3106d8341209fb180d408bbec12efd7606a3e82d49d5a385c2a1b279fddd9418816d0e970a3a80cf18eec2df8d1fca0baf4e857554dc24ecde21dd5db3b14eb47a2134d4fe85c2b6aebef2f6f4fac3b0a7bcba55c9ffe41a42aadb2c83105dc52dd52d18bf96762a61a8e16fa0cf3483805ca20bc9426d26d0b2ecb6c503df9a2645225a2022302bb0eac71d657172342c014ede2192dc262c8130300885e4a8e2143baf3ade136e69517825a46d1a3f3f09e755abfb37b9f69f06ecc5d40684e810647b45fe9db54d2147b8c2fe3c51a4fd0241f8fdd10524b90cb30656ff6721d32e3181eb60fbc0f6b51cad2b209a4e3749210c6d92eb95a73d8932a3a1a3f7d90bba89614fccaaa0ae7bd003812d13e32ef8059afb1da22fbbff2905dabf72508ec9cbad0ddc4db48817bcf2679900caacfd646910f9efbb4dcf71795eea0cfaccae07ac4cadc8d170aaa47aaecaf436249cc57623abf712e7674e9a7203ed03ba6caac5cdc93f7fc2677530637be49205792dea7a1959e646ef0a9a08cbc8f3184ad641f31ce01aa09752b2315c142d7aab10c127169430289418f702a53edff517123b6d7680c7cf9340fd72e4b65805a70f9813af84cbc154bd573bce451a09e76209c5f29f90d79c3214cea6f6ea3711f9085999fa53af22df6050f8f660a5828abe783a2003278dd8ec3e421ce23f8966403b7dcf7924bc52cdd6bc7b915eda749a4b3a9b3a00be492905267e21be92859bbee31f43fefbf3f581d9a5b85a39d2456e48904be01f3c57d7e9ba224e07a173e4eefc8eb9b72169a659f934d0f37722b7dd95fed98e474d5c7e9bb4e35a37d21f4808ccbf3d673a35e0e0008c827992cc0cd18de77477424eda776c18016a98322e2effcc21ce63552757a7808a638a11942b0ccd27930d71210923cffcc45d2905b80e971fdcbfd28f880895db832f10882ce04286ff7c78c17be2a4c204024688a2d0a2579217e7ac2b7d5ab1bc8b0398986403c45a900d47885094423054410f8fd126664b7383f46bc3906d97d1265b2c6268dd693d145ee008086ad060c9274891c80d5dd1ba535cc30818958bfe237677e1f5acba1ebe8964643e182f01f462f4c2e4e74ffffab06d20957621ab752ba455d9bde7c45bb1bed7f77d41c8c3d8d29a8786b8920f507afdf0e6af2db414d9c4ff97402914cd99e4e18",
    .str_x963_full_key="049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a728b52ec2c7388924f45554f8cfe5a9c94921aa6551a36694f5a31588e09cd260c7cde9dff1a8ba477ae7e29f5a7feedecc6379f79a036ade1b53249c9ef9db8",
    .retval=0,
},
{ // 17: SecureBackup. Same as #16 but prefix with FF to trigger a retry
.cp=&ccec_cp_256,
.flags=(CCEC_GENKEY_DETERMINISTIC_SECBKP),
.str_entropy="abdd2f6268f3fdfa1ef7f8961706766f05dc7958f17ad94cb9d21c7be35e2c8fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9887733279980412d767772d0ec320d01101580ad68151885c74e500612183f3ebab9ad6d7b9dd93a3c5be9be7233991909f95d08f1b70762d74341546045a83f1e6e394ff70ad17731cf54da69d9202e98ed363693ba4930e2a19ec69891a2afb09f7a2cb8e9e9e1219349d12729380e06abc100cde3faa7c5018ecb5537ddc54bc34d2ed524d72c43f0de3106d8341209fb180d408bbec12efd7606a3e82d49d5a385c2a1b279fddd9418816d0e970a3a80cf18eec2df8d1fca0baf4e857554dc24ecde21dd5db3b14eb47a2134d4fe85c2b6aebef2f6f4fac3b0a7bcba55c9ffe41a42aadb2c83105dc52dd52d18bf96762a61a8e16fa0cf3483805ca20bc9426d26d0b2ecb6c503df9a2645225a2022302bb0eac71d657172342c014ede2192dc262c8130300885e4a8e2143baf3ade136e69517825a46d1a3f3f09e755abfb37b9f69f06ecc5d40684e810647b45fe9db54d2147b8c2fe3c51a4fd0241f8fdd10524b90cb30656ff6721d32e3181eb60fbc0f6b51cad2b209a4e3749210c6d92eb95a73d8932a3a1a3f7d90bba89614fccaaa0ae7bd003812d13e32ef8059afb1da22fbbff2905dabf72508ec9cbad0ddc4db48817bcf2679900caacfd646910f9efbb4dcf71795eea0cfaccae07ac4cadc8d170aaa47aaecaf436249cc57623abf712e7674e9a7203ed03ba6caac5cdc93f7fc2677530637be49205792dea7a1959e646ef0a9a08cbc8f3184ad641f31ce01aa09752b2315c142d7aab10c127169430289418f702a53edff517123b6d7680c7cf9340fd72e4b65805a70f9813af84cbc154bd573bce451a09e76209c5f29f90d79c3214cea6f6ea3711f9085999fa53af22df6050f8f660a5828abe783a2003278dd8ec3e421ce23f8966403b7dcf7924bc52cdd6bc7b915eda749a4b3a9b3a00be492905267e21be92859bbee31f43fefbf3f581d9a5b85a39d2456e48904be01f3c57d7e9ba224e07a173e4eefc8eb9b72169a659f934d0f37722b7dd95fed98e474d5c7e9bb4e35a37d21f4808ccbf3d673a35e0e0008c827992cc0cd18de77477424eda776c18016a98322e2effcc21ce63552757a7808a638a11942b0ccd27930d71210923cffcc45d2905b80e971fdcbfd28f880895db832f10882ce04286ff7c78c17be2a4c204024688a2d0a2579217e7ac2b7d5ab1bc8b0398986403c45a900d47885094423054410f8fd126664b7383f46bc3906d97d1265b2c6268dd693d145ee008086ad060c9274891c80d5dd1ba535cc30818958bfe237677e1f5acba1ebe8964643e182f01f462f4c2e4e74ffffab06d20957621ab752ba455d9bde7c45bb1bed7f77d41c8c3d8d29a8786b8920f507afdf0e6af2db414d9c4ff97402914cd99e4e18",
.str_x963_full_key="049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a728b52ec2c7388924f45554f8cfe5a9c94921aa6551a36694f5a31588e09cd260c7cde9dff1a8ba477ae7e29f5a7feedecc6379f79a036ade1b53249c9ef9db8",
.retval=0,
},

