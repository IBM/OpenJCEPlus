/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.DHKey;
import java.math.BigInteger;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

public final class DHParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private static final DHParameterSpec params_512;
    private static final DHParameterSpec params_768;
    private static final DHParameterSpec params_1024;
    private static final DHParameterSpec params_2048;
    private static final DHParameterSpec params_3072;
    private static final DHParameterSpec params_4096;
    private static final DHParameterSpec params_6144;
    private static final DHParameterSpec params_8192;

    private OpenJCEPlusProvider provider = null;
    private int keysize = 0;
    private int exponentSize = 0;

    /*
     * How to generate P and G parameters - 512, 768, 1024, 2048, 3072 - these
     * parameters can reuse pregenerated values from DSAParameterGenerator. For
     * bit sizes 4096, 6144 and 8192 - nohup openssl dhparam -out
     * dhparams<keysize>.pem -5 <keysize> cat dhparams<keysize>.pem | openssl
     * dhparam -noout -text > keysize.txt> Copy P from <keysize>.txt to
     * variables below and convert them to a hex String by removing spaces and :
     * OpenSSL is available on Mac, Linux or Cygwin Windows
     */

    static {
        // p,g, 512
        BigInteger p_512 = new BigInteger(
                "00e9d9399927c743d7117fd0eedf2a556e57be08390e62924b4bc66cf3266457f6843673cbad906187286a9b44ab64cf86d613ed5fdf6a67b8b648d747b729418b",
                16);

        BigInteger g_512 = new BigInteger("5", 16);

        params_512 = new DHParameterSpec(p_512, g_512);

        // p,g, 768
        BigInteger p_768 = new BigInteger(
                "00fe7229e2416eb1a1dff1b2a7835ea2d06922074f50de22d4846ae4d9587701451f2aacd5c1ffc47b71a6c17b1a105e2163f5dafd225ee0f33f2f915b7af7d09eecbd2e507288b99a5efc39f4727b1352e9b8bf1dfb428c3d061660fd89f81cdf",
                16);

        BigInteger g_768 = new BigInteger("5", 16);

        params_768 = new DHParameterSpec(p_768, g_768);

        // p,q,g, 1024
        BigInteger p_1024 = new BigInteger(
                "00b500b886816dee366bbf163e6d378f2bf2dcbdea738eff15dbe4e5b784b82ed41a20b882e5f882b1e2d445d23b60e1f245043eda032edb59b197a3f177c8d5807f32386f4a2c9ade1bbdf2b600393481b6b481cb2a50d2b6f04c63c0463a6f625913d72134de0ef6e4e72fe2f62cc43b6df32684294c124afdd0b3036d84139b",
                16);

        BigInteger g_1024 = new BigInteger("5", 16);

        params_1024 = new DHParameterSpec(p_1024, g_1024);

        // p,g, 2048
        BigInteger p_2048 = new BigInteger(
                "00c3933e51dbd4823e5b3e730a06922a41fadd0ad1b6dcbdc8f8b39541b2232fc89896002640e47552f708836f0abfb78d988e37fa802f7b9ce5a04930fbcf8b17d59e9db8560ebc71ef70e32f214572df581722dfd9d41a81ca8770fb561b4ddfce913f73a2f243832a176efb8a234e467c918b3da0879097cd995eb85fdb160290dc8550b09ff0782f7388e3d478afae17f171a3ebba2bb3e93b8b73d37b2cdc06cb93e36d1937f266b2de197dee63b00146d760ad9309dc89e5cdc1a5e2bc0021b755987ffab5fdd352bb856a01eb0bcf13afb4852c0ff50986923d77bbdb7c7b5b46af735d2e7966a848b114ae73f675ddc9c07835621ad839f525a38fea5b",
                16);

        BigInteger g_2048 = new BigInteger("5", 16);

        params_2048 = new DHParameterSpec(p_2048, g_2048);

        // p,g, 3072
        BigInteger p_3072 = new BigInteger(
                "00af32a9da586df87991b6cd4d1dacca7689abe8d2c8e7f4448ad62704a0ad1504cd36f23c9da4ac8988022f2868b5c07aee707bccb3b45c2867fc357ce02e532439cb796b7f427c9726cf55ebcd9a32245ce4b0c9edc09fdef77034d87fb39041b23cc43580bf0f95f774f778df7d172ab06ba243ee4ffcda04908dcdd63c3b10c8cfb58739df40532f0d30c99c49dc164703083ea6f42243344d137a2d7dd001c04f3c9df76bf5849ca844adbfb95e4ed8782c356e125f91d91361ae980ba4317cbf3ca59b32f5e04dab027b4c549d49e0f0555dd0eeb864ea3af482ae57fd2ba6d04109308bf753de524f398db097e0657aa713856b6f3d8492ae62fa1a0fc8121831ae2114f1f80d1f6f7ae207a901fd4fcf05e294196743ad43f2faff1b60e1fd63debec3f0b4e2708feb2b426f4fc59b2d1f7d2d3ea9015bd6de6d00cb5fcdd717d074ee58de55ce424a7427242cbb8f32a8b5c5b452e754da0e6ff9dda63be8a6f2865083b1be511e5c237678a829118b43535eb07011ec93dd3c74d71b",
                16);

        BigInteger g_3072 = new BigInteger("5", 16);

        params_3072 = new DHParameterSpec(p_3072, g_3072);

        // p,g, 4096

        BigInteger p_4096 = new BigInteger("00bffcbc796f5f5abc038bd0f5425b"
                + "434c9c841b61aeada4babb733fed0f" + "4862c892f9eb0d18f63c6543b0dd90"
                + "53be2067414803e5f88ff10b2af5ae" + "7a3a91b888a918f32699af4d5649fb"
                + "11056954620bd3eac082c975934368" + "6f51ffebadc5ed6f01bfe3ad17418a"
                + "a167b8ce539bd8793b8cbce1b552ce" + "1c19067fd79f3ca6ec43ded82da84f"
                + "06dc26baac741f74518ca7bde76c5e" + "9767bbfd2548cf90ca7e928905c8df"
                + "1a15462d58ba539f1d37050ef77559" + "5226ddb42aa900481560e4419c0719"
                + "b73927417d7c1f9db30edb1421a77c" + "b4e8b46e7d8fb40df64efbb29e7fb0"
                + "ef163a59cf33b8a9e21979cc383842" + "2057a46e64679e48edafcd014dd464"
                + "4abd26350bb6cc35daea22d43e70ef" + "6564630f2cfd9261bd64c346afb3e0"
                + "8533b67c5702d9edb14cd695bd490e" + "f4db1fce0fabaa78b8f0248b44098f"
                + "f1bf21b4ade769bbe25e8a39eb0ea9" + "b974e3630af226807efce8dce15353"
                + "d79bdb30656585dd556778e27cbdc1" + "d1f60c33560e4c80ff39249c6bcc16"
                + "675fc6a1c228821e45bbb1b0fcaa98" + "c8f84b6340bfa9282c03bc66566fa3"
                + "8e82d8fee481f02ea5b5f5742f8aca" + "4aa4aad1ade687dbded4ec0dfa6856"
                + "7bcc4dbe009e4384b7762d38cbcf07" + "36626dcac6b27470642225c4414966"
                + "24de3d44edf55ae7dc58c30aded35e" + "dcc4eff89494948f20946a2f0dddcd"
                + "c0edf952e63a6c7597b8a2627c7054" + "ae644b", 16);
        BigInteger g_4096 = new BigInteger("5", 16);

        params_4096 = new DHParameterSpec(p_4096, g_4096);

        // p,g, 6144
        BigInteger p_6144 = new BigInteger("00ee44c7210997bc150de5179bdd70"
                + "11f9cb032d8c2d6ffda5d45f9e7166" + "004aa8d30581405454c7cbb84ba39b"
                + "864513c1c388b89956d3191613036b" + "825620d5048c53f09374cd00484c07"
                + "41871961998169d1d7b87f11714d84" + "222649e1d7f5c1e9a1c98313958dc6"
                + "9cf3a0197c71369e0193c62b70c526" + "22e01e6c1d14f054de505910cbe594"
                + "0d69698dfd08afad4b2c3da06d5e06" + "8f1d96e29d17f6ada88f5339783648"
                + "bd43ca19edf33a59d3bfaa47743372" + "b315c858da5c5c4a4015fbac013b1c"
                + "f250812a35c80676ac289435659cb3" + "f8f7e7380e86e634303977c5ac331e"
                + "390798043e25921890e5b10b9c7a82" + "020b7b5a29a7105c1640e3f635ed01"
                + "aed002f6d6d6258ce874dbeaf8129d" + "dd50086607f54d552e3c9da4a935c6"
                + "b715776c0b97cc8e249546bcd39110" + "49877f5521d78cddb177819c96f529"
                + "61129ed5c6d948f68a14aa68231b11" + "aaedea491e42f17986f4524273193e"
                + "d68c03d3c5b7f83ccfc28eb3f0bc88" + "7df84a02dbb0e847ec52558b72c293"
                + "27010440859026a6c7de02a309edcb" + "dfc452c7167c3af97974a59e4e279f"
                + "bf23e6378eb476d0588c48f69431a9" + "339b4eba9df0725c7fec44ee0cea71"
                + "d0143246f982721a4aba325a7da1e9" + "85f888a43243582c6bc0707c0ff950"
                + "20a72f177a5207d59d7cc15f430f38" + "ec45f6ac502d7a81ab016cc6128a3d"
                + "3c7bc9ad830f60529eb2aee98b58e1" + "f2a913d63339b818fcb5e325cc90ba"
                + "fa51cf73e3137a59aaec368dc69bc3" + "302acac0351ebf39e14d93e97353ac"
                + "f808a87121a088e2c97f85c4aa5d61" + "ab6d4e33f7f88ec8b4ea4fbb9158a8"
                + "48142f105357b72869174e3de18bcb" + "9dd368ce988a0092ca93821a3bdf87"
                + "fad0761de3f5f3d2e349a67c6fe85a" + "89681300c4ee2d8b21f8bf2b426f9c"
                + "31dde2348c5bcef0a5008fcdb4c234" + "363e3c91e506e574e5fc35474ae749"
                + "0ea304020ea96732aa9d2b6c668728" + "318a836ad53e30426968a0245fdcd8"
                + "a797ed7a3e48b4976c580c379b1d9e" + "d7155ed864200877667f3e81c0e3e0"
                + "97038d27a12d71671e8b04689a4ec7" + "6eabfe4e8607a2575d1bd3d1cb4fd7" + "7e3d4b8b",
                16);

        BigInteger g_6144 = new BigInteger("5", 16);

        params_6144 = new DHParameterSpec(p_6144, g_6144);

        // p,g, 8192

        BigInteger p_8192 = new BigInteger("00c164c46dbb0596c77938a260999a"
                + "bfec25cc6368e789f1483891784d35" + "09707426319aa5c5d66361a29f4cb0"
                + "cf8abaf32c81f08b3edf1d599ca15d" + "4a11d95cedaa7ec3b9677bc28ef9aa"
                + "86d6b9a5d7f425d0d5243ba2afb67a" + "c94a1007729d9e053d41c7ef5e0e4c"
                + "ec815c1a98a0ed5860f0b99dea9d40" + "9afb4825f58b54e5865ae17c6e20de"
                + "5e2d9b45bc916ebaba157a0f5b6ddb" + "e5aca5e9461f42afc7001bd73d2933"
                + "cff1e6efed2265ecbe16c5586dc7e4" + "db9fe5d760047b1bcee97ca7b06e58"
                + "46ee5f197fa862a53dd05565903fc6" + "2ea87156a9cefafabbeacc13e017c6"
                + "a71097379d3ed83e56d45b17221455" + "a6e11ad3e8e1032d87d572471c93ad"
                + "504d67ffd55ea4586b966b7389cc8b" + "16e535e6ca822244fb293cc7100627"
                + "67bf19607c46dde5926b0100c479fc" + "5731177a309d84a46d8dabc50d5b8a"
                + "3c26f1316edb6cbddc28acb2f25560" + "1f292b5f6bb2dc5e3f4a9b7cc44a93"
                + "dbd775b4559eea91c89ca232e60590" + "c5b54c1bcc9037542f38ef0c1109fd"
                + "c6a684f64cb958b9fba757a1717d03" + "40dec22dc8b77ee853d2272ddbf7c9"
                + "dfe11a776d20bf117c7eab2bf0ec7b" + "f208f1ad359c0eb85658796471f863"
                + "1584fc3f68f647a1064aa4dafa08f9" + "754739840bc6ba016544c963fda63d"
                + "97b8a0b50c30bfccf2180bf18a4cbe" + "708cae982f2fbcb39341a7f2f90aa0"
                + "2fceb0c795393a2e9eadb54a206db6" + "862442627a17897c30ac2e33a6135e"
                + "6816f2aed8e692ed4b5012d8f4e696" + "916f2c82c1719190c284146b6c794d"
                + "a617c52da1a63a303c5dfa8afa93e4" + "beaadab0b121be4812e5b5ffbae09c"
                + "1c8ffde32707908aa7b7361cd76d9e" + "aaf095fb91e5b2300f2e87eaa71c49"
                + "1ca25d3cfdcd259e60ffceca650aa5" + "41aec8fac6dc5d05d9c3189ec59e27"
                + "292e02d4a67aba7e895a110e0fb62e" + "cfee6492cb5e9bd4fe579abfdcd5a0"
                + "c5da48d93213e7002579922741ab2b" + "283b459fd949da212b723392a3e1dd"
                + "b62ae23d42d9c6a49d7fe84046e3f5" + "b808a900bb8e52f358823e9eec31fc"
                + "986ee2ad8b0bdf4234a818e1dbad0b" + "95d38b0789340b531f403580435659"
                + "6f1c386c6853b78cbf7f7d745013b9" + "07e5c24af35b81b69c5cdc674a06e1"
                + "ac3a728e09b00a9ac9e788ace68b6a" + "4a556598e410666bc29357188faeb3"
                + "8be56e5691c17ab72163910fe7f9d0" + "1f8c8468bdf6ba9845a2873b0339c1"
                + "855263a59abded562b1f40efd49b81" + "fac9d7f5054be04e51ca0055ff1360"
                + "f6dc66b8886b5f9b2389e36b9213aa" + "01e33cba2ac337592b986a436d0e05"
                + "58521c1d6e9a173bf66c4742bc8ba5" + "91390032f5a3e9a0a25b5035c0f0f9"
                + "94869436b37853bf8400a1f435b61a" + "ba3be39c3c6b2936aff805a2fe0797"
                + "16fd71be634f8ff90018a68b5aaeb8" + "2d6cfe1bb6f0e577e38d3364ea0aa8"
                + "a1ad165aa95c6de0d4a079eda2898a" + "9cd76f45e3", 16);

        BigInteger g_8192 = new BigInteger("5", 16);

        params_8192 = new DHParameterSpec(p_8192, g_8192);
    }

    private static void checkKeySize(int keysize) throws InvalidParameterException {

        boolean supported = ((keysize == 2048) || (keysize == 3072) || (keysize == 4096)
                || (keysize == 6144) || (keysize == 8192)
                || ((keysize >= 512) && (keysize <= 1024) && ((keysize & 0x3F) == 0)));

        if (!supported) {
            throw new InvalidParameterException("DH key size must be multiple of 64 and range "
                    + "from 512 to 1024 (inclusive), or 2048, 3072 or 4096 or 6144 or 8192 "
                    + "The specific key size " + keysize + " is not supported");
        }
    }

    public DHParameterGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    @Override
    protected void engineInit(int size, SecureRandom random) {

        checkKeySize(size);
        this.keysize = size;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (genParamSpec instanceof DHGenParameterSpec == false) {
            throw new InvalidAlgorithmParameterException(
                    "Params must be instance of DHGenParameterSpec");
        }

        DHGenParameterSpec dhParamSpec = (DHGenParameterSpec) genParamSpec;
        keysize = dhParamSpec.getPrimeSize();
        exponentSize = dhParamSpec.getExponentSize();
        if ((exponentSize <= 0) || (exponentSize >= keysize)) {
            throw new InvalidAlgorithmParameterException("Exponent size (" + exponentSize
                    + ") must be positive and less than modulus size (" + keysize + ")");
        }
        try {
            checkKeySize(keysize);
        } catch (InvalidParameterException ipe) {
            throw new InvalidAlgorithmParameterException(ipe.getMessage());
        }

    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {

        try {
            DHParameterSpec dhParamSpec = DHParameterGenerator.getPrecomputedParameters(keysize);
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("DH", provider);
            if (dhParamSpec != null) {
                algParams.init(dhParamSpec);
                return algParams;
            }

            if (keysize > 0) {
                byte[] encodedParams = DHKey.generateParameters(provider.getOCKContext(),
                        this.keysize);
                algParams.init(encodedParams);
                return algParams;
            } else {

                throw new ProviderException("DHGenParameterSpec not supported");
            }

        } catch (Exception e) {
            throw provider.providerException("Failure in generateGenerateParameters", e);
        }
    }

    protected static DHParameterSpec getPrecomputedParameters(int keySize) {

        switch (keySize) {
            case 512:
                return params_512;
            case 768:
                return params_768;
            case 1024:
                return params_1024;
            case 2048:
                return params_2048;
            case 3072:
                return params_3072;
            case 4096:
                return params_4096;
            case 6144:
                return params_6144;
            case 8192:
                return params_8192;
        }

        return null;
    }

}
