/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.DSAKey;
import java.math.BigInteger;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAGenParameterSpec;
import java.security.spec.DSAParameterSpec;

public final class DSAParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private static final DSAParameterSpec params_512;
    private static final DSAParameterSpec params_768;
    private static final DSAParameterSpec params_1024;
    private static final DSAParameterSpec params_2048;
    private static final DSAParameterSpec params_3072;

    private OpenJCEPlusProvider provider;
    private int keysize = 0;

    static {
        // p,q,g, 512
        BigInteger p_512 = new BigInteger(
                "fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17",
                16);
        BigInteger q_512 = new BigInteger("962eddcc369cba8ebb260ee6b6a126d9346e38c5", 16);
        BigInteger g_512 = new BigInteger(
                "678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4",
                16);
        params_512 = new DSAParameterSpec(p_512, q_512, g_512);

        // p,q,g, 768
        BigInteger p_768 = new BigInteger(
                "e9e642599d355f37c97ffd3567120b8e25c9cd43e927b3a9670fbec5d890141922d2c3b3ad2480093799869d1e846aab49fab0ad26d2ce6a22219d470bce7d777d4a21fbe9c270b57f607002f3cef8393694cf45ee3688c11a8c56ab127a3daf",
                16);
        BigInteger q_768 = new BigInteger("9cdbd84c9f1ac2f38d0f80f42ab952e7338bf511", 16);
        BigInteger g_768 = new BigInteger(
                "30470ad5a005fb14ce2d9dcd87e38bc7d1b1c5facbaecbe95f190aa7a31d23c4dbbcbe06174544401a5b2c020965d8c2bd2171d3668445771f74ba084d2029d83c1c158547f3a9f1a2715be23d51ae4d3e5a1f6a7064f316933a346d3f529252",
                16);
        params_768 = new DSAParameterSpec(p_768, q_768, g_768);

        // p,q,g, 1024
        BigInteger p_1024 = new BigInteger(
                "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",
                16);
        BigInteger q_1024 = new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5", 16);
        BigInteger g_1024 = new BigInteger(
                "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",
                16);
        params_1024 = new DSAParameterSpec(p_1024, q_1024, g_1024);

        // p,q,g, 2048
        BigInteger p_2048 = new BigInteger(
                "c115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0df4115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0de4115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0dd4115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0dc4115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0db4115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0da4115bc66e841220d6abfe599889f6fe197c49dd298899d0042d975770567a0d8a33e8495af620db327e75cb79ca8052ed2c4aa4e58e219a7026639669ef0113d",
                16);
        BigInteger q_2048 = new BigInteger(
                "e9550410aa0c0e1c6e1c19b68c3868d90c0b3c0f0d3a328548ed9c9b01628d33", 16);
        BigInteger g_2048 = new BigInteger(
                "859e4107d0e0ace09b35a6ea852fe0cf1b24de409eefb72bb5248710dde913078f6a91528b4f018d50ba43489221ff681156ff9f2a62e9d18dae17e6b9de93726c4f28858e34edfc153089f93587fbfd86ca042929422d7891d8956a94c9ba3183210e6cda1b470d342258e9ab21e704e7bd0a9a4f209d1414be360da4bfaccda253e45235b096c06251c45c4df2180b032ada3333f0ec9bc56c4852b30552af415fa0997f5b94637dc53cc54ef6056ae1e7e6e79e46d74a9d43528451df7488c7d5e3ea59ead4d2b3f6d238a2feeee4c7ba219bf18bc796f91cb6ba7a7b9782dc98cdfc2a10ed31946b4c4f302dedf6b153273723d7b86ba8ca62b2506d0e3e",
                16);
        params_2048 = new DSAParameterSpec(p_2048, q_2048, g_2048);

        // p,q,g, 3072
        BigInteger p_3072 = new BigInteger(
                "008b18d5a8426f1a911f9e17d29bdf41bec9b4bc7adb198c4c6fd002ccd6d9c99045a24c62a75dae50bd4529726db3f8c138c529db23e0689ddc565f11f6789c937833d49ee6cdbc9cd061a7124296adcf614cc3f96c942abff04b3d415449ebd0d5bd5f06d241ac9c02891faea381506a70c0cfe951ab1d201ac9083614caeb8cbc885ed76ad737574142008803f8fb925d96dc07dee8ba58b3b35e6423ee257ac622ad94b14f5fb1bfeca9abdb2cef62c0d514bbd0b2ad6b544574ef5950d583748f3bc3bcaacb64699ded01b5d6e7a0e8104a4016c4446e3fd6520f51e84fed2e41767f82fd46aae3b91205c7a2bc82ada75f551872da332e23f171a8b8192819ad2cebe399562f39fbafa0d60d85460654affe972575c3022c8c7e14655c4472fb1531f3067085a1065fed4af135fc336723383d97a3deb0d8454bab5f4edb8639eade677251f90eb4a1ae68cc62fccb817d6413a0bcfe31fb0da5d24dab0fe8f9480c1da8c31ace0e23ec41cf4951d0d8fbf33fca665773b3e13780a629a5",
                16);
        BigInteger q_3072 = new BigInteger(
                "00aca428c675133389cfcf3d1a8268aaebd561274b4ace368239ba9b1e46637b4b", 16);
        BigInteger g_3072 = new BigInteger(
                "4331e9fb8670de24d451522690ac957ecc5e404fa4df8cbc6961d9e0877d808ea6ae0f5308a47b0a57787c05d85bde0e91ad9aaca2a0c46302e5c156a72e207c87d039dd797d512f4627dceea3c3d00532849009f57bd9eb9993a173905dcf7b61a7b9494382c197a31142d5ab7c5cd3d89f26359f2b7af2cde69445c56c639638151b53ddf152e1e6ba1178fe7e4b0ce6bc06330918578e40d50c854d60d528f11b09350bc76e42069f19edd9abef2baf9772f6405caf5076596f6d3ee6812e91c4e70b624871d1669d62fd66d312e43fb4a05f1d9a75f56888083543ee87d1f30690735722f20444d5668848be762515ec5a376ec564cfdf1744bd6b0bc8923af9433879a68a8bba8a9512eaf7060944ef55167290a09289ccc200da88d7a9216473ecf7a1abec764701464f251ced497968a8a0cc3e3b735e0eaf9b1d75e31e05bcfaa9e5d3e69cee08ede5f12ce26667ab51e511d3b9792d494c9b96ca040262ac9552901b09e850458b68ce0ef7018b39a7b1194f0c2da22e3e61a83cfe",
                16);
        params_3072 = new DSAParameterSpec(p_3072, q_3072, g_3072);
    }

    public DSAParameterGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    @Override
    protected void engineInit(int modlen, SecureRandom random) {
        int subPrimeLen = DSAKeyFactory.getDefaultSubprimeLen(modlen);

        try {
            DSAKeyFactory.checkStrength(provider, modlen, subPrimeLen);
        } catch (InvalidKeyException e) {
            throw new InvalidParameterException(e.getMessage());
        }

        this.keysize = modlen;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (genParamSpec instanceof DSAGenParameterSpec == false) {
            throw new InvalidAlgorithmParameterException(
                    "Params must be instance of DSAGenParameterSpec");
        }

        DSAGenParameterSpec dsaGenParams = (DSAGenParameterSpec) genParamSpec;
        // This support is added because JCK tests expect to pass it.
        // qLen and seedLen from genParamSpec are ignored, because
        // either the precomputed parameters are used or
        // OCK generates the parameters based on the pLen (key size)
        try {
            DSAKeyFactory.checkStrength(provider, dsaGenParams.getPrimePLength(),
                    DSAKeyFactory.getDefaultSubprimeLen(dsaGenParams.getPrimePLength()));
        } catch (InvalidKeyException e) {
            throw new InvalidParameterException(e.getMessage());
        }
        this.keysize = dsaGenParams.getPrimePLength();
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        try {

            DSAParameterSpec dsaParamSpec = DSAParameterGenerator.getPrecomputedParameters(keysize,
                    provider);
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("DSA", provider);
            if (dsaParamSpec != null) {
                algParams.init(dsaParamSpec);
                return algParams;
            }

            if (keysize > 0) {
                byte[] encodedParams = DSAKey.generateParameters(provider.getOCKContext(),
                        this.keysize);
                algParams.init(encodedParams);
            } else {
                throw new ProviderException("Invalid key size: " + keysize);
            }
            return algParams;
        } catch (Exception e) {
            throw provider.providerException("Failure in generateGenerateParameters", e);
        }
    }

    static DSAParameterSpec getPrecomputedParameters(int size, OpenJCEPlusProvider provider) {
        int minSizeP = provider.isFIPS() ? DSAKeyFactory.MIN_PRIME_SIZE_FIPS
                : DSAKeyFactory.MIN_PRIME_SIZE_NONFIPS;
        if (provider.isFIPS() && size < minSizeP) {
            return null;
        }
        switch (size) {
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
        }

        return null;
    }
}
