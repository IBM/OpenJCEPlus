/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
 * Run subset of KAT (Known-Answer Tests) from http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 */

public class BaseTestAESGCM_ExtIV extends BaseTest {

    // --------------------------------------------------------------------------
    //
    //
    private KeyGenerator aesKeyGen = null;
    private SecretKey key = null;
    private AlgorithmParameters params = null;
    private Cipher cipher = null;

    private AlgorithmParameterSpec gcm_param_spec = null;

    private static Class<?> classGCMParameterSpec = null;
    private static Constructor<?> ctorGCMParameterSpec = null;
    private static Method methGCMParameterSpecSetADD = null;

    private static Class<?> classAESGCMCipher = null;
    private static Constructor<?> ctorAESGCMCipher = null;
    private static Method methAESGCMCipherUpdateAAD = null;

    private static Method methCipherGetInstance = null;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestAESGCM_ExtIV(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    protected void setUp() throws Exception {

        /*
         * Try constructing a javax.crypto.spec.GCMParameterSpec instance (Java
         * 7+)
         */

        try {
            classGCMParameterSpec = Class.forName("javax.crypto.spec.GCMParameterSpec");
            ctorGCMParameterSpec = classGCMParameterSpec
                    .getConstructor(new Class<?>[] {int.class, byte[].class});
            classAESGCMCipher = Class.forName("javax.crypto.Cipher");
            methAESGCMCipherUpdateAAD = classAESGCMCipher.getMethod("updateAAD",
                    new Class<?>[] {byte[].class});
        } catch (Exception ex) {
            /* Differ to calling code in test cases that follow... */
        }

        /*
         * Try constructing an ibm.security.internal.spec.GCMParameterSpec
         * instance (IBM Java 6)
         */

        if (ctorGCMParameterSpec == null) {
            try {
                classGCMParameterSpec = Class
                        .forName("ibm.security.internal.spec.GCMParameterSpec");
                ctorGCMParameterSpec = classGCMParameterSpec
                        .getConstructor(new Class<?>[] {int.class, byte[].class});
                methGCMParameterSpecSetADD = classGCMParameterSpec.getMethod("setAAD",
                        new Class<?>[] {byte[].class, int.class, int.class});
            } catch (Exception ex) {
                /* Differ to calling code in test cases that follow... */
            }
        }

        byte[] iv = new byte[16];// com.ibm.crypto.plus.provider.AESConstants.AES_BLOCK_SIZE];
        SecureRandom rnd = new java.security.SecureRandom();
        rnd.nextBytes(iv);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_ExtIV_Test00() throws Exception {
        runTestEncrypt(104, // init_tag_length,
                "66a3c722ccf9709525650973ecc100a9", // str_key_bytes,
                "1621d42d3a6d42a2d2bf9494", // str_init_vec,
                "61fa9dbbed2190fbc2ffabf5d2ea4ff8", // str_plain_text,
                "d7a9b6523b8827068a6354a6d166c6b9", // str_added_auth_data,
                "fef3b20f40e08a49637cc82f4c89b860", // str_cipher_text,
                "3fd5c0132acfab97b5fff651c4"); // str_tag
    }

    public void testAESGCM_ExtIV_Test01() throws Exception {
        runTestEncrypt(104, // init_tag_length,
                "d9821b713dae03c8f246ff3fd65454d7", // str_key_bytes,
                "6e34f3ffc9a602dda2764c56", // str_init_vec,
                "6fca787a081b5517d6c887147a2ef097", // str_plain_text,
                "f76d8fd6ab2e4ce3e3316b3523fc24a7", // str_added_auth_data,
                "17ad843de0ff22f0c6a96c7cb6eaeadb", // str_cipher_text,
                "e6f91e55ad30c74b9f94577375"); // str_tag
    }

    public void testAESGCM_ExtIV_Test02() throws Exception {
        runTestEncrypt(128, // init_tag_length,
                "89850dd398e1f1e28443a33d40162664", // str_key_bytes,
                "e462c58482fe8264aeeb7231", // str_init_vec,
                "2805cdefb3ef6cc35cd1f169f98da81a", // str_plain_text,
                "d74e99d1bdaa712864eec422ac507bddbe2b0d4633cd3dff29ce5059b49fe868526c59a2a3a604457bc2afea866e7606", // str_added_auth_data,
                "ba80e244b7fc9025cd031d0f63677e06", // str_cipher_text,
                "d84a8c3eac57d1bb0e890a8f461d1065"); // str_tag
    }

    public void testAESGCM_ExtIV_Test03() throws Exception {
        runTestEncrypt(64, // init_tag_length,
                "41d0e604d7be7bc069bcc725e6b9ac1d", // str_key_bytes,
                "99", // str_init_vec,
                "", // str_plain_text,
                "f14ec0d5cdd1cb1aa902f9f9d48ffc770269f186", // str_added_auth_data,
                "", // str_cipher_text,
                "81c928129992ba8d"); // str_tag
    }

    public void testAESGCM_ExtIV_Test04() throws Exception {
        runTestEncrypt(64, // init_tag_length,
                "7e95066b60093f66175493d141359dbd", // str_key_bytes,
                "4057da04c773361c33be7f10d7ba708b2278503fd7b0a6dd130a962952b8887d6a412074c1572eb0c53edf81ee701cabc60552aceb0f662697d3b2acc037eab9445242bff4496606b8cfbf2d3c72874b769b9b63234b64d429829f467305acab4ae8d45c8f7c4f5b5771cb7cbdccc8c7273a4a2038464fadfdf733b631179017", // str_init_vec,
                "5ea1312e26c95bcf005b617423", // str_plain_text,
                "660c28a460fa93e112aac6ceb54a80a2", // str_added_auth_data,
                "5517fba376ab16c7e2ad16c1e2", // str_cipher_text,
                "4fd94671abde616e"); // str_tag
    }

    public void testAESGCM_ExtIV_Test05() throws Exception {
        runTestEncrypt(32, // init_tag_length,
                "62dc8e1a98863c7de64f30b74c01d530", // str_key_bytes,
                "e9f658589f973895510cb34eef99b0cf34fc311c20c21464e07c4d6d34a15fcad3ea9ef51ef05513fb700cbb92aeef35e4cdda47b2c06c1104e987afa1cd6f827e7bc5a8db6d0657345945c068cabfd6e6b57533c929fe5804e121809b8b43d050a211fbee319879b1ba4cc2768df3a92014839086a377663a1d1967d7c602e9", // str_init_vec,
                "f2c54a35286a225389e853e51f3f64b6980a79262e5545856c053d558d87d7b739eb75f27587efe219eb82e9a176fa14419dbe", // str_plain_text,
                "5d78b486c29131866569768d5eedb61afc48de7d1a223d0cccc647cf35408bb932293f3bc1b51a504e13c27548d083c8e8a45d4e9d4dc923c3c2bde38d6cdeaed2929b67e371356f74f635b3b1183ee0db71476f2024e1f5e13c", // str_added_auth_data,
                "fe0c3ae08418ef91b478360942a84a58f8d93df7fe5bde138f59cc23432f04b9637841ccf7a5d539a36f621a7d17e026d4cc2c", // str_cipher_text,
                "e413041a"); // str_tag
    }

    public void testAESGCM_ExtIV_Test06() throws Exception {
        runTestEncrypt(128, // init_tag_length,
                "aa740abfadcda779220d3b406c5d7ec09a77fe9d94104539", // str_key_bytes,
                "ab2265b4c168955561f04315", // str_init_vec,
                "", // str_plain_text,
                "", // str_added_auth_data,
                "", // str_cipher_text,
                "f149e2b5f0adaa9842ca5f45b768a8fc"); // str_tag
    }

    public void testAESGCM_ExtIV_Test07() throws Exception {
        runTestEncrypt(120, // init_tag_length,
                "d74a0b3c2172b1692c5c22741d0cfb2dc898dc100b584a1b", // str_key_bytes,
                "f182415b8d5c62f4c83a501fe07ffa635baf2ba506fa141aa6e0f1e957b3f6c14dac93df25ebddd6679ba1857bdc4126644abb50dc2742a207f96a653b1fadb6654fccc5e01270ce0a75e2ea3d7ba9e3b6d4f29d58a98cd977fdf592cd130369cd07012b02be3122b2f6b781c91c9d518fa872cdcf55e0add504a55bf4dfaf88", // str_init_vec,
                "", // str_plain_text,
                "8a5a55c9b332e05ed5840b629eac4fbc5384e8a1aaa41014e0c0135bed2bab0cbe952a5e69861cffe815cd6135af69dd", // str_added_auth_data,
                "", // str_cipher_text,
                "20ff32821d8532b54c7101858b9b88"); // str_tag
    }

    public void testAESGCM_ExtIV_Test08() throws Exception {
        runTestEncrypt(128, // init_tag_length,
                "a23dfb84b5976b46b1830d93bcf61941cae5e409e4f5551dc684bdcef9876480", // str_key_bytes,
                "5aa345908048de10a2bd3d32", // str_init_vec,
                "", // str_plain_text,
                "", // str_added_auth_data,
                "", // str_cipher_text,
                "f28217649230bd7a40a9a4ddabc67c43"); // str_tag
    }

    public void testAESGCM_ExtIV_Test09() throws Exception {
        runTestEncrypt(112, // init_tag_length,
                "368b486ee83404c9a839f1829c12f064b84788577ba171ab5bf50a54a67b901e", // str_key_bytes,
                "9676aff9526356b31c0e4816", // str_init_vec,
                "", // str_plain_text,
                "", // str_added_auth_data,
                "", // str_cipher_text,
                "d6a90ccddf478c250f8b84bcc6a"); // str_tag
    }

    public void testAESGCM_ExtIV_Test10() throws Exception {
        runTestEncrypt(96, // init_tag_length,
                "b33b0e4c5b9f7ef77cec1a29ed5844bda3853238bdf7766e7645029931f169f0", // str_key_bytes,
                "f226d65e8654fdf5193ed721", // str_init_vec,
                "bcf48ddcfe9d011a1003973d68d2d78a", // str_plain_text,
                "", // str_added_auth_data,
                "d2eb20898a301b5d8e69e99262720213", // str_cipher_text,
                "93af01abb6a970047a7fc010"); // str_tag
    }

    public void testAESGCM_ExtIV_Test11() throws Exception {
        runTestDecrypt(128, // init_tag_length,
                "cf063a34d4a9a76c2c86787d3f96db71", // str_key_bytes,
                "113b9785971864c83b01c787", // str_init_vec,
                "", // str_plain_text,
                "", // str_added_auth_data,
                "", // str_cipher_text,
                "72ac8493e3a5228b5d130a69d2510e42"); // str_tag
    }

    public void testAESGCM_ExtIV_Test12() throws Exception {
        runTestDecrypt(120, // init_tag_length,
                "6dfa1a07c14f978020ace450ad663d18", // str_key_bytes,
                "34edfa462a14c6969a680ec1", // str_init_vec,
                "", // str_plain_text,
                "2a35c7f5f8578e919a581c60500c04f6", // str_added_auth_data,
                "", // str_cipher_text,
                "751f3098d59cf4ea1d2fb0853bde1c"); // str_tag
    }

    public void testAESGCM_ExtIV_Test13() throws Exception {
        runTestDecrypt(112, // init_tag_length,
                "4ccbed984d83124fbc8646aaaa0cad56", // str_key_bytes,
                "4b8b033debe4101ecc919af0", // str_init_vec,
                "6f6fd0c4a687103864d1a7627c0e5609", // str_plain_text,
                "", // str_added_auth_data,
                "2a9e6fd8e29b2243a2a77aaa800715d1", // str_cipher_text,
                "106844f33ac3667d7ca6e0e4f38b"); // str_tag
    }

    public void testAESGCM_ExtIV_Test14() throws Exception {
        runTestDecrypt(104, // init_tag_length,
                "e029db25c48151c44a089c31dbb7e8d7", // str_key_bytes,
                "45bc625220177ec34cd40520", // str_init_vec,
                "32e71839645c61b9b4e87982fc7969b9", // str_plain_text,
                "c8b22d9dc3d69ace3ad244fa28c45356db4f9365fe9fa78ebf745f7ba35b7d80d7e84bd8a852ecc909fc18e786168ab6", // str_added_auth_data,
                "2465cba64812c3510d66e3c33e3630e7", // str_cipher_text,
                "b94ed63b00aa5eeeea9558e135"); // str_tag
    }

    public void testAESGCM_ExtIV_Test15() throws Exception {
        runTestDecrypt(96, // init_tag_length,
                "94a16fd10c3f34082d443909d076127b", // str_key_bytes,
                "3a", // str_init_vec,
                "", // str_plain_text,
                "", // str_added_auth_data,
                "", // str_cipher_text,
                "c723b505654410ad9d5112a8"); // str_tag
    }

    public void testAESGCM_ExtIV_Test16() throws Exception {
        runTestDecrypt(96, // init_tag_length,
                "748dd62db5ec077e08aaf77243de11ec1794ee66a8d897e4", // str_key_bytes,
                "3f", // str_init_vec,
                "3df86bcfb966a941a0a6d1f5ecfebc74a755bcbf8710ba4e5b8b09447682ecbd", // str_plain_text,
                "4182ec57a21254c0c18d996a2733a009e4f2765a", // str_added_auth_data,
                "7229f54926cecb2ae842c89044c32725bed785fae537d74937595bcb3e02f647", // str_cipher_text,
                "984a39fecd9c61ca9a6fdabc"); // str_tag
    }

    public void testAESGCM_ExtIV_Test17() throws Exception {
        runTestDecrypt(64, // init_tag_length,
                "8a68f0860f05db6d688e38c3dd931b7e1c476df9ea835fd5", // str_key_bytes,
                "99", // str_init_vec,
                "03ca877225df6b1ff0079f0ec88b13b097fc15ca35354fab55656437feb3f0df", // str_plain_text,
                "e7073b10fec236065adf88962444de109b9eea3b2ec60b2d337fe9105d3958060440670b8d77f5493f23343b121d32c3ee3fbb7ead8dbcb4ac0c3e4d240d103f9d11875ae9e47546a92e329f58628ab951d2372f7e3941ec15be", // str_added_auth_data,
                "6741d4a89a14c3ce88643f706e44a7bce3298e8f8adac05188264603717b1bd5", // str_cipher_text,
                "014089a8a0c53bed"); // str_tag
    }

    public void testAESGCM_ExtIV_Test18() throws Exception {
        runTestDecrypt(32, // init_tag_length,
                "d0f31becae6c6f526b686b468c14bafcbdab4aaf3f6a7892", // str_key_bytes,
                "fee500667abd1d9d3f78479e986987c40763e0406d1a05afd7baa036131adac3453e488d00c002ddca5babbf393dc2e64305c4b1b57356f576877cd019de7c76e6d187b969a63782eaadca4e1884622207b35b70edcda2fefb1e1618ca102ef4d1a4c04ca9840de26544279e1fa368c14a26c5ca320d9dfc29c15876819c683f", // str_init_vec,
                "b9cb82ebe010700ff9a3d45678", // str_plain_text,
                "", // str_added_auth_data,
                "a439f3175e645ecf05c5a9cc70", // str_cipher_text,
                "3e5f75c9"); // str_tag
    }

    public void testAESGCM_ExtIV_Test19() throws Exception {
        runTestDecrypt(64, // init_tag_length,
                "cc71a2842d54ebf3eaac8aeb6ac59cd30f2672b190f18c7ad5bcced5567401b7", // str_key_bytes,
                "95e7daf83268ba04f006cfc0d5596a5dd672707dcb6b33a0edb95673317b133a8cf8fa127603eb63d79155200a0c7fc91226b02e08cff7888428e89becbead89707e3e11a3e55b0f670102e464f42964f1aa6dcfc02ba7adf6240c465e18e708d4f65d9d3b63b2f36a829ddc1adb4dcfc4861d6e949bfd211c829a4d90d490e4", // str_init_vec,
                "04725ecfe0072b5a49a3c68beacfcdf237a900662d1767af218928b6f724c5b8d912033161ba874e8d99d8d175710d284bf310", // str_plain_text,
                "", // str_added_auth_data,
                "4a385c74888d214865c3fb7958384b48312f1a605dac52d77802d17dafcd487aa30627cbc1b23e2ad2e92756c0e6d91fbd1417", // str_cipher_text,
                "e1507520c358afec"); // str_tag
    }

    public void testAESGCM_ExtIV_Test20() throws Exception {
        runTestDecrypt(64, // init_tag_length,
                "f7b640b7d59b4938689139e1f14179a9388f84c89852e045c568930da83c7521", // str_key_bytes,
                "ae273c5bbc4858b7836bafdc52536bdfb2d9ce5c4eb8d18f4161fee0bc2646277ec255b038bcf685d05395933a0e50a87ffda1354db09dc22ab88725e72d4f462d195a2fa738582fae43ea023d00aee55dbd8561fbfebfd191faf3d53c5b07bf5964e81c0072dc39a32c4a5f7d3318527ae7a187b95d9b5232d44439aa44dc81", // str_init_vec,
                "2162cc5fe44a5d4ebfc026d90cedae01d5d1daeb0751820afb8cda16d0e43f4e498bfbf74c490efa88f87edb03e98619de7a39", // str_plain_text,
                "359b76e8dd0f6f54526c37741beb49deb4460d2e20175a93c805391dabc14da4f496a5db9ce882f2ac5e6276d9a20b8a9a14142372db0c9dfbab710ae92160c1ea9aa7069276cfa16bad4bd28869dbc8a163e9560d6c478da8bc", // str_added_auth_data,
                "1bd0594edd6a58eaf63e67e473a78aeb8bde55febaa726bc663c05f4ba11cc30cb2e2bac4a7f240263b3ab6777a980ad65f662", // str_cipher_text,
                "45d81bc44c0a8ab4"); // str_tag
    }

    public void testAESGCM_ExtIV_Test21() throws Exception {
        runTestDecryptFail(128, // init_tag_length,
                "a49a5e26a2f8cb63d05546c2a62f5343", // str_key_bytes,
                "907763b19b9b4ab6bd4f0281", // str_init_vec,
                "", // str_plain_text,
                "", // str_added_auth_data,
                "", // str_cipher_text,
                "a2be08210d8c470a8df6e8fbd79ec5cf"); // str_tag
    }

    public void testAESGCM_ExtIV_Test22() throws Exception {
        runTestDecryptFail(104, // init_tag_length,
                "4be099b41ca9753a1ee2c390128717f0", // str_key_bytes,
                "4c8caf0975557503121c9cc4", // str_init_vec,
                "", // str_plain_text,
                "6f57079b419f8c96173e3eacd09461552f59b201abd97ea12c9e51581b52afada8cdae3f7c9647f42a53908eac447678", // str_added_auth_data,
                "127c70b259e5e23ab46b1ebde1a94906", // str_cipher_text,
                "d4e80f72dcd5e9c80ca16bf0c4"); // str_tag
    }

    public void testAESGCM_ExtIV_Test23() throws Exception {
        runTestDecryptFail(120, // init_tag_length,
                "64d8c86131e97843f5aee06bd6e56f321e779bf8a1c8d4c0", // str_key_bytes,
                "62e1b55d7b20d2370d25c94f0d7d65a90e39a63c8dea4dc550c7f722a57b31e205272c7538e0a94377fcbaefa90e9f068dcb525ba35136f096c3818c806b40b797a5c5aa9d4a8cd3a62440c55ac88a0ba3ceaca55592b94da5751467096a02312cd75d34360269509ac1cf7a0866dbeae4b42dbb66ace73d54a3c24c530f756b", // str_init_vec,
                "", // str_plain_text,
                "08d1900dce22ed8315722c0e0b1fc27b", // str_added_auth_data,
                "291e06145e8ec81001a9abf9f4", // str_cipher_text,
                "e1e1e01085ffd36c4ca2f8a94593a1"); // str_tag
    }

    public void testAESGCM_ExtIV_Test24() throws Exception {
        runTestDecryptFail(64, // init_tag_length,
                "01643b56c34eb12ab7a4f4223636201b954ec56019b4d1f0", // str_key_bytes,
                "7f25be91cf728d011a7c165e6c51ffed58d89e493f7b0ed740018e8b2223196aadf8deab678bd3672fbea4d139c1b1d3789fcb819a462fa8ba66b855795efd2c6b898b181ec75fb9503cde3b241c597386936301680921400eb3480b7c6e81be8cda674407fe17fbffc99b87eb51021748292bec8ebaf754ce595d6b2d6082bd", // str_init_vec,
                "", // str_plain_text,
                "b355fa75c60005d186a435e2b2f42802", // str_added_auth_data,
                "629d4db4520283dcdcb4019987", // str_cipher_text,
                "266685ebed5dab3d"); // str_tag
    }

    public void testAESGCM_ExtIV_Test25() throws Exception {
        runTestDecryptFail(32, // init_tag_length,
                "2bcc18d95b3137479f15dce3a0220adeea720032d64f7686", // str_key_bytes,
                "190c0228ddb9370cc3aeb542ea0b353b3481871649a5e346792a3aae4e8153232b93db7b58db0fd583dc97dd8a169fdb55003d339842493a861afca2870a9746107cea1fd62e791c311e247647c4f0f928ed0433fb1f997464d76b46dc1f5311a6c210c5c00675d2b8d8e5b633fe67678d0b8e3292b56bf00e85e937d860a193", // str_init_vec,
                "", // str_plain_text,
                "38196c56b36d86ca2ccb12e7e7fd0797", // str_added_auth_data,
                "98bdce993dbf402b7b160aee01", // str_cipher_text,
                "348a2cfa"); // str_tag
    }

    public void testAESGCM_ExtIV_Test26() throws Exception {
        runTestDecryptFail(96, // init_tag_length,
                "55680523b7056ac2c365393b9c7bdff3df75528e73baf67ffa615323b9e84543", // str_key_bytes,
                "9369d44147e81bf35716e813702f67435d05901a16ff3540767c33db4bc6645fa3e3b144d7ff04beb2c086fff6b09190f101c5abae2bfb34abf893bceb2f621d29618e7a98f1ff53bc7033cac9f02eb84a5c9e91cff333448e8c4dde6b35327acf8c9675be03dde136ab1d91d02012af5c53b73c3a75c9e4c0e535bcc86a4ac6", // str_init_vec,
                "", // str_plain_text,
                "78b8d7d0c2a6f368fc28e274054f65e08fbc1208233f461aa61bae6952952c0e730cb756c7d07d175a8aa58ca97e54a28f0d881e39f3d4c01f5c586f14254ba1bb2c9f829fbad1a4b270bb4f5a18fe0d8764d01bda85c6438d72", // str_added_auth_data,
                "950931ba46c6c29ffd54f49eec850a5ce88a6b97a8d16ee36ffa2dd7b632250d140f4c2c265e06efed3c2a282d60cfb8158f31", // str_cipher_text,
                "8aaa9e6b012f5ca26dd237a1"); // str_tag
    }

    public void testAESGCM_ExtIV_Test27() throws Exception {
        runTestDecryptFail(112, // init_tag_length,
                "fb5dcada6ee653f69e2e5946c661141e9e1665b4cd0a1cba", // str_key_bytes,
                "5e5eac3fa667144ec67e45a6b8b0f62d89eab45c9032404fd97fa37e643babfa962781f530165c94697719beda2500d1ab5c28ae567cc8f68232484b0749a6601504f2586f5031f9a85da343e20140399db0121dcdc2ceeb8ff0c1f1e58235f7af82d9619bb367df5358d747c5b2bea63b8ae75b7b5637780dce3526da138384", // str_init_vec,
                "", // str_plain_text,
                "f68924b04034b53903402716509053ef7471db582292555acbfd9a442aa614bef58c6e12c284ec127276c52e5fd73eef", // str_added_auth_data,
                "", // str_cipher_text,
                "d4893f0edeabc8f16f219ee12cb4"); // str_tag
    }

    // --------------------------------------------------------------------------
    //
    //
    public void runTestEncrypt(int init_tag_length, String key_bytes, String init_vec,
            String plain_text, String added_auth_data, String cipher_text, String tag)
            throws Exception {
        runTestEncrypt(init_tag_length, asciiToHex(key_bytes), asciiToHex(init_vec),
                asciiToHex(plain_text), asciiToHex(added_auth_data), asciiToHex(cipher_text),
                asciiToHex(tag));
    }

    // --------------------------------------------------------------------------
    //
    //
    public void runTestEncrypt(int init_tag_length, byte[] key_bytes, byte[] init_vec,
            byte[] plain_text, byte[] added_auth_data, byte[] cipher_text, byte[] tag)
            throws Exception {

        //Assume.assumeTrue( javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= (key_bytes.length * 8) );
        if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < (key_bytes.length * 8)) {
            return;
        }

        gcm_param_spec = (AlgorithmParameterSpec) ctorGCMParameterSpec.newInstance(init_tag_length,
                init_vec);

        /* For Java 6 */
        if (methGCMParameterSpecSetADD != null) {
            methGCMParameterSpecSetADD.invoke(gcm_param_spec, added_auth_data, 0,
                    added_auth_data.length);
        }

        SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");

        cipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcm_param_spec);

        /* For Java 7/8 */
        if (methGCMParameterSpecSetADD == null) {
            methAESGCMCipherUpdateAAD.invoke(cipher, added_auth_data);
        }

        byte[] output_text = cipher.doFinal(plain_text);

        if (byteEqual(output_text, 0, cipher_text, 0, cipher_text.length) == false) {
            //System.out.println("runTestEncrypt - Cipher text mismatch");
            //System.out.println("output_text - " + hexToAscii(output_text));
            //System.out.println("cipher_text - " + hexToAscii(cipher_text));
            fail("Cipher text mismatch");
        }

        if (byteEqual(output_text, cipher_text.length, tag, 0, tag.length) == false) {
            //System.out.println("runTestEncrypt - Authentication tag mismatch");
            //System.out.println("output_text - " + hexToAscii(output_text));
            //System.out.println("cipher_text - " + hexToAscii(cipher_text));
            fail("Authentication tag mismatch");
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void runTestDecrypt(int init_tag_length, String key_bytes, String init_vec,
            String plain_text, String added_auth_data, String cipher_text, String tag)
            throws Exception {
        runTestDecrypt(init_tag_length, asciiToHex(key_bytes), asciiToHex(init_vec),
                asciiToHex(plain_text), asciiToHex(added_auth_data), asciiToHex(cipher_text),
                asciiToHex(tag));
    }

    // --------------------------------------------------------------------------
    //
    //
    public void runTestDecrypt(int init_tag_length, byte[] key_bytes, byte[] init_vec,
            byte[] plain_text, byte[] added_auth_data, byte[] cipher_text, byte[] tag)
            throws Exception {

        //Assume.assumeTrue( javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= (key_bytes.length * 8) );
        if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < (key_bytes.length * 8)) {
            return;
        }

        byte[] new_cipher_text = new byte[cipher_text.length + tag.length];
        System.arraycopy(cipher_text, 0, new_cipher_text, 0, cipher_text.length);
        System.arraycopy(tag, 0, new_cipher_text, cipher_text.length, tag.length);
        cipher_text = new_cipher_text;

        gcm_param_spec = (AlgorithmParameterSpec) ctorGCMParameterSpec.newInstance(init_tag_length,
                init_vec);

        /* For Java 6 */
        if (methGCMParameterSpecSetADD != null) {
            methGCMParameterSpecSetADD.invoke(gcm_param_spec, added_auth_data, 0,
                    added_auth_data.length);
        }

        SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");

        cipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        cipher.init(Cipher.DECRYPT_MODE, key, gcm_param_spec);

        /* For Java 7/8 */
        if (methGCMParameterSpecSetADD == null) {
            methAESGCMCipherUpdateAAD.invoke(cipher, added_auth_data);
        }

        byte[] output_text = cipher.doFinal(cipher_text);

        if (byteEqual(output_text, 0, plain_text, 0, plain_text.length) == false) {
            //System.out.println("runTestDecrypt - Cipher text mismatch");
            //System.out.println("output_text - " + hexToAscii(output_text));
            //System.out.println("plain_text - " + hexToAscii(plain_text));
            fail("Cipher text mismatch");
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void runTestDecryptFail(int init_tag_length, String key_bytes, String init_vec,
            String plain_text, String added_auth_data, String cipher_text, String tag)
            throws Exception {
        runTestDecryptFail(init_tag_length, asciiToHex(key_bytes), asciiToHex(init_vec),
                asciiToHex(plain_text), asciiToHex(added_auth_data), asciiToHex(cipher_text),
                asciiToHex(tag));
    }

    // --------------------------------------------------------------------------
    //
    //
    public void runTestDecryptFail(int init_tag_length, byte[] key_bytes, byte[] init_vec,
            byte[] plain_text, byte[] added_auth_data, byte[] cipher_text, byte[] tag)
            throws Exception {

        //Assume.assumeTrue( javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= (key_bytes.length * 8) );
        if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < (key_bytes.length * 8)) {
            return;
        }

        byte[] new_cipher_text = new byte[cipher_text.length + tag.length];
        System.arraycopy(cipher_text, 0, new_cipher_text, 0, cipher_text.length);
        System.arraycopy(tag, 0, new_cipher_text, cipher_text.length, tag.length);
        cipher_text = new_cipher_text;

        try {
            gcm_param_spec = (AlgorithmParameterSpec) ctorGCMParameterSpec
                    .newInstance(init_tag_length, init_vec);

            /* For Java 6 */
            if (methGCMParameterSpecSetADD != null) {
                methGCMParameterSpecSetADD.invoke(gcm_param_spec, added_auth_data, 0,
                        added_auth_data.length);
            }

            SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");

            cipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            cipher.init(Cipher.DECRYPT_MODE, key, gcm_param_spec);

            /* For Java 7/8 */
            if (methGCMParameterSpecSetADD == null) {
                methAESGCMCipherUpdateAAD.invoke(cipher, added_auth_data);
            }

            cipher.doFinal(cipher_text);

            fail("Did not get expected AEADBadTagException");
        } catch (Exception ex) {
            if (ex.getClass().getSimpleName().equals("AEADBadTagException")) {
                return;
            } else {
                //ex.printStackTrace();
                //System.out.println("Unexpected exception: " + ex.getMessage());
                fail("Did not get expected AEADBadTagException");
            }
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    private boolean byteEqual(byte[] b1, int offset1, byte[] b2, int offset2, int len) {
        if (((b1.length - offset1) < len) || ((b2.length - offset2) < len)) {
            return false;
        }

        for (int i = 0; i < len; i++) {
            if (b1[i + offset1] != b2[i + offset2]) {
                return false;
            }
        }
        return true;
    }

    // --------------------------------------------------------------------------
    //
    //
    public static String hexToAscii(byte[] b) {
        char[] hexDigits = "0123456789abcdef".toCharArray();
        if (b == null) {
            return "(null)";
        }
        StringBuffer sb = new StringBuffer(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            int k = b[i] & 0xff;
            if (i != 0) {
                sb.append(':');
            }
            sb.append(hexDigits[k >>> 4]);
            sb.append(hexDigits[k & 0xf]);
        }
        return sb.toString();
    }

    // --------------------------------------------------------------------------
    //
    //
    public static byte[] asciiToHex(String s) {
        try {
            int n = s.length();
            ByteArrayOutputStream out = null;
            if (s.contains(":")) {
                out = new ByteArrayOutputStream(n / 3);
            } else {
                out = new ByteArrayOutputStream(n / 2);
            }

            StringReader r = new StringReader(s);
            while (true) {
                int b1 = nextNibble(r);
                if (b1 < 0) {
                    break;
                }
                int b2 = nextNibble(r);
                if (b2 < 0) {
                    break;
                }
                int b = (b1 << 4) | b2;
                out.write(b);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public static int nextNibble(StringReader r) throws IOException {
        while (true) {
            int ch = r.read();
            if (ch == -1) {
                return -1;
            } else if ((ch >= '0') && (ch <= '9')) {
                return ch - '0';
            } else if ((ch >= 'a') && (ch <= 'f')) {
                return ch - 'a' + 10;
            } else if ((ch >= 'A') && (ch <= 'F')) {
                return ch - 'A' + 10;
            }
        }
    }
}

