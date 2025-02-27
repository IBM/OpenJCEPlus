/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class BaseTestDHKeyFactory extends BaseTestJunit5Interop {

    @Test
    public void testDHKeyFactory() throws Exception {

        test_dh_keyFactory(getInteropProviderName(), getInteropProviderName());
        test_dh_keyFactory(getProviderName(), getProviderName());
        if (getProviderName().equals("OpenJCEPlusFIPS")
                || getInteropProviderName().equals("OpenJCEPlusFIPS")) {
            // OpenJCEPlusFIPS will not work with the static DHParams from IBMJCE. They are no longer FIPS usable.
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                test_dh_keyFactory(getProviderName(), getInteropProviderName());
            } else {
                test_dh_keyFactory(getInteropProviderName(), getProviderName());
            }
        } else {
            test_dh_keyFactory(getProviderName(), getInteropProviderName());
            test_dh_keyFactory(getInteropProviderName(), getProviderName());
        }

    }

    @Test
    public void testDHShortSecret1() throws Exception {
        test_dh_short_secret(getProviderName(), getProviderName());
        test_dh_short_secret(getInteropProviderName(), getInteropProviderName());
        test_dh_short_secret(getProviderName(), getInteropProviderName());
        test_dh_short_secret(getInteropProviderName(), getProviderName());
    }

    @Test
    public void testDHShortSecret2a() throws Exception {
        test_dh_short_secret2ndmethod(getProviderName(), getProviderName());
    }

    @Test
    public void testDHShortSecret2b() throws Exception {

        test_dh_short_secret2ndmethod(getInteropProviderName(), getInteropProviderName());


    }

    @Test
    public void testDHShortSecret2c() throws Exception {

        test_dh_short_secret2ndmethod(getProviderName(), getInteropProviderName());

    }

    @Test
    public void testDHShortSecret2d() throws Exception {

        test_dh_short_secret2ndmethod(getInteropProviderName(), getProviderName());

    }



    void test_dh_short_secret2ndmethod(String providerNameX, String providerNameY)
            throws Exception {



        byte[] aPrivKeyEnc = new BigInteger(
                "308202260201003082011706092a864886f70d010301308201080282010100c3933e51dbd4823e5b3e730a06922a41fadd0ad1b6dcbdc8f8b39541b2232fc89896002640e47552f708836f0abfb78d988e37fa802f7b9ce5a04930fbcf8b17d59e9db8560ebc71ef70e32f214572df581722dfd9d41a81ca8770fb561b4ddfce913f73a2f243832a176efb8a234e467c918b3da0879097cd995eb85fdb160290dc8550b09ff0782f7388e3d478afae17f171a3ebba2bb3e93b8b73d37b2cdc06cb93e36d1937f266b2de197dee63b00146d760ad9309dc89e5cdc1a5e2bc0021b755987ffab5fdd352bb856a01eb0bcf13afb4852c0ff50986923d77bbdb7c7b5b46af735d2e7966a848b114ae73f675ddc9c07835621ad839f525a38fea5b02010504820104028201004f18d73f8bc2930b10a43a871ca82e60bcdaefb433a496e13edb02d7bc68f569d398ac477336effe55733788ccb4d10c1f5782637a8367773b5c4c131f30eddd30e55ddcec21e049af9ca42bde4d671728a8f501efa345c6bd3b6d7d694b7f626728a3dec899a427c9abc87e38219184079202d9c258c7075ac24b047b33edcc590d88cc1989b0b2e1f78da68b01facec7941f32bdd857996250ab28a65caa30638110a85a0d8b5a641ecce62de2b82c119f63771319723a501de5b5ba0aafda34232e74e0cec500f886ca5e3687dd54dbda3de01359d8b35d9d54f47eb8b9b18f8f835326d2d02ce18c2f5b4332c152ea09efe51e5cb050212a38aad4504f20",
                16).toByteArray();


        byte[] aPubKeyEnc = new BigInteger(
                "308202253082011706092a864886f70d010301308201080282010100c3933e51dbd4823e5b3e730a06922a41fadd0ad1b6dcbdc8f8b39541b2232fc89896002640e47552f708836f0abfb78d988e37fa802f7b9ce5a04930fbcf8b17d59e9db8560ebc71ef70e32f214572df581722dfd9d41a81ca8770fb561b4ddfce913f73a2f243832a176efb8a234e467c918b3da0879097cd995eb85fdb160290dc8550b09ff0782f7388e3d478afae17f171a3ebba2bb3e93b8b73d37b2cdc06cb93e36d1937f266b2de197dee63b00146d760ad9309dc89e5cdc1a5e2bc0021b755987ffab5fdd352bb856a01eb0bcf13afb4852c0ff50986923d77bbdb7c7b5b46af735d2e7966a848b114ae73f675ddc9c07835621ad839f525a38fea5b02010503820106000282010100c0ee5d8f78eefcb0fd99dba96a80d03ed76bdc973ac7fb76123019a412f1d4558c6d5a6e617edfd2fb7e641ecc24ed8d310639885d82bd89a2b66571a4ffecd8edb433442ccf22e1af2aa26c7db81dfdb855bef6a25c6f67027b1ab08b2c9f30be1c2bfc54ef8d4da5a0facee44ca4a96da5be835de94f15b4d6f95c4b2e7989cba0212c8006ffb8b41446ce2bf3d7aa59a907c38544989cc7931b2aabb86de697c0230b94eee372c666459cefd60804be45be131a0c5ebe0a0256a50e19e4432e318563713336dc3985c54ca0a564b97b728a6284ae439b3199833950a11cdaaf965aba6114c9cb60db6ea75a1e74f2ee38739c824dd1db8a0e32ba64eac855",
                16).toByteArray();

        byte[] bPrivKeyEnc = new BigInteger(
                "308202260201003082011706092a864886f70d010301308201080282010100c3933e51dbd4823e5b3e730a06922a41fadd0ad1b6dcbdc8f8b39541b2232fc89896002640e47552f708836f0abfb78d988e37fa802f7b9ce5a04930fbcf8b17d59e9db8560ebc71ef70e32f214572df581722dfd9d41a81ca8770fb561b4ddfce913f73a2f243832a176efb8a234e467c918b3da0879097cd995eb85fdb160290dc8550b09ff0782f7388e3d478afae17f171a3ebba2bb3e93b8b73d37b2cdc06cb93e36d1937f266b2de197dee63b00146d760ad9309dc89e5cdc1a5e2bc0021b755987ffab5fdd352bb856a01eb0bcf13afb4852c0ff50986923d77bbdb7c7b5b46af735d2e7966a848b114ae73f675ddc9c07835621ad839f525a38fea5b02010504820104028201005c3392676ad46ae17879b4ee05d1c8549a7a60238238886ad9701304ba0b819e1d2204d7c76075ec0ba89b7b480acbbd57fe719d4603b63417167cd72ae4decb74e71d1514aefdb6845aff3face8d40de2b38104e101a5a64a7feeae95f86958d2edc8520d99e061600919a6a6d0b9ea95be2e8547f551ddc5298094893ea8b3c87f2442423f30752bf994bc77f33d2de2b0ee18c410b2801052969f86edd4241f374f3c366ff2626f5942ce26412044e1a377b3f159c53f04ba8e804b85dbfa72e901b1da796c3b955e08db643d9a93d98d03474c2bf3e40a403c269846a3b68974ded600c058c050a0a5a7c567c6634b5a667271000b78da82cd2281ddb323",
                16).toByteArray();

        byte[] bPubKeyEnc = new BigInteger(
                "308202243082011706092a864886f70d010301308201080282010100c3933e51dbd4823e5b3e730a06922a41fadd0ad1b6dcbdc8f8b39541b2232fc89896002640e47552f708836f0abfb78d988e37fa802f7b9ce5a04930fbcf8b17d59e9db8560ebc71ef70e32f214572df581722dfd9d41a81ca8770fb561b4ddfce913f73a2f243832a176efb8a234e467c918b3da0879097cd995eb85fdb160290dc8550b09ff0782f7388e3d478afae17f171a3ebba2bb3e93b8b73d37b2cdc06cb93e36d1937f266b2de197dee63b00146d760ad9309dc89e5cdc1a5e2bc0021b755987ffab5fdd352bb856a01eb0bcf13afb4852c0ff50986923d77bbdb7c7b5b46af735d2e7966a848b114ae73f675ddc9c07835621ad839f525a38fea5b020105038201050002820100676e024feba026c7451df30ad69d3a68e087efc01cfbb7c0765b53e85f83aa840c8a4c6dad960358d2eb0d3bc8ebd539620e1bce38479a097f0b816ec992619d4b9841939bc38dc05838c95becbde7aa6537a6af5dc6cfb21f5396526f3906bee63c1ebd1ce7af2c5fd70b6cdfbd5e44d25ef9114090aaab6b23ec8c9474064edafe7320c11bc52bf24f889532579b50aa20357cebc9c8991832206df36931e6b05a8ab89f723a7a2cd1f1d1e796d20ffa2c0f2ac3e75e32e9becbe9611b0a6050e3e3aa575a8750f7f38e57299556a2ee8b8e246b82e7a81e4dc51a1e13308a064f543f3239b2b05d3e5e12a1963ebb611db795c4edf6cba15a9642fed37058",
                16).toByteArray();

        KeyFactory aKeyFac = KeyFactory.getInstance("DH", providerNameX);
        X509EncodedKeySpec x509KeySpecForB = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpecForB);

        PrivateKey aPrivKey = aKeyFac.generatePrivate(new PKCS8EncodedKeySpec(aPrivKeyEnc));

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", providerNameX);
        aKeyAgree.init(aPrivKey);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */

        KeyFactory bKeyFac = KeyFactory.getInstance("DH", providerNameY);
        X509EncodedKeySpec x509KeySpecForA = new X509EncodedKeySpec(aPubKeyEnc);
        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpecForA);

        PrivateKey bPrivKey = bKeyFac.generatePrivate(new PKCS8EncodedKeySpec(bPrivKeyEnc));

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", providerNameY);
        bKeyAgree.init(bPrivKey);



        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        //

    }

    void test_dh_short_secret(String providerNameX, String providerNameY) throws Exception {


        // A encodes A's public key, and sends it over to B.
        byte[] aPrivKeyEnc = new BigInteger(
                "308202260201003082011706092a864886f70d010301308201080282010100d931d5890af0a4998888a74a4304d4ea4c20ab1b76f9531e5b3147e17f535f9f559a9bc8925bb4bc2968c415937ebae78cedb8a6af5617212d174f72fac275b375c31bdeb246aa04fdde6fb232ce867720faafdc01232e747596f5b5bd3b1de5724364a0c231d9010498df65790452e094b0dcd7064a31471fdacaa99ad54fab9c8696f65d0ce25e48b0cf19fa431588d4e9212cca0c040758f1b07730441adfdb4a219da5ffd77da61c35bb305549ce79b9abfc2e0864fcb6de8a91880b660437e410a2502119502d39f45666e3498e89e3f9f2a73b1d2f31c25de940120594f852ce586e9fc5b7784bcbd9bb6083ad79d218540cbb751983a2ec82b4e9c12b02010204820104028201004e74cf4c4735d48dd7937fc5845c6bfc61146220e086fe1b2734c6be02dd158ebf64e1ee919793fdf710f342fc9e5e2215a90f8906e07833eb02244dd3c580827d00c5e1e51bf5d273217ca740741516ef034602901168e909457e73012173a0da2fb7150bf477d763e8e15e54b00eda1d5a108a9edef6ba37f2e5d3da5fd209d41d8108b0a7f1647940bd27e12f0524792f0ce5413b9d320219d86479b41ac16f24ba0925995fe042a42884559a83e01c03d3ddda4fc0660d286ee9e8b6806873ec3a36f5937626a06ea289588caa71c5788b1a920ea2097f05525860929810dff94d5ed679e4fcdfbf8cd518264ee90b156491bb460a93f3db49c4cf94b19b",
                16).toByteArray();
        byte[] aPubKeyEnc = new BigInteger(
                "308202243082011706092a864886f70d010301308201080282010100d931d5890af0a4998888a74a4304d4ea4c20ab1b76f9531e5b3147e17f535f9f559a9bc8925bb4bc2968c415937ebae78cedb8a6af5617212d174f72fac275b375c31bdeb246aa04fdde6fb232ce867720faafdc01232e747596f5b5bd3b1de5724364a0c231d9010498df65790452e094b0dcd7064a31471fdacaa99ad54fab9c8696f65d0ce25e48b0cf19fa431588d4e9212cca0c040758f1b07730441adfdb4a219da5ffd77da61c35bb305549ce79b9abfc2e0864fcb6de8a91880b660437e410a2502119502d39f45666e3498e89e3f9f2a73b1d2f31c25de940120594f852ce586e9fc5b7784bcbd9bb6083ad79d218540cbb751983a2ec82b4e9c12b020102038201050002820100279f3beff993e1925fc290e0e187f54a9c799a5f0ad8a194bdac35979d5a22f2e3c3f818a9045b0f7c4970ddf92d75d10d2c80ba2d5798184323d0217403b4172f1b1ae9bdbb05aa272c4524b9beb0178cc3a381604f01b3f3dbe076b895d17009fb5dc90740c83c372b12ac1c689c17f5b0535f3823644ad3d2e3ffd020955cb8d113a9d8a69c438afd388f07a900faed405859e74110dc24e01b582330e2febe930261f3cdb97caf43a7c04698e4335bb8b0366a4fcf9970625da82eb2e6531c4bd5af8ae4a6df81567b43cf21b1e042be95af23da7c192025d0bd272f63eacc5f3cccd41809c889d50369c2fd158140c4fa306e263a808c44ce6c7f1cf866",
                16).toByteArray();
        byte[] bPrivKeyEnc = new BigInteger(
                "308201a90201003082011b06092a864886f70d0103013082010c0282010100d931d5890af0a4998888a74a4304d4ea4c20ab1b76f9531e5b3147e17f535f9f559a9bc8925bb4bc2968c415937ebae78cedb8a6af5617212d174f72fac275b375c31bdeb246aa04fdde6fb232ce867720faafdc01232e747596f5b5bd3b1de5724364a0c231d9010498df65790452e094b0dcd7064a31471fdacaa99ad54fab9c8696f65d0ce25e48b0cf19fa431588d4e9212cca0c040758f1b07730441adfdb4a219da5ffd77da61c35bb305549ce79b9abfc2e0864fcb6de8a91880b660437e410a2502119502d39f45666e3498e89e3f9f2a73b1d2f31c25de940120594f852ce586e9fc5b7784bcbd9bb6083ad79d218540cbb751983a2ec82b4e9c12b020102020204000481840281810093de665ecb2e839af8cec72eb4e157532260026340d288473fa7aeea65383a6586acfb8f9fcfcfb53ed5592ebcb397c016598666d56036fc199f133d8665773f411c3bba7121a63244fb1372119cdc390d80d49b2e59f3e66d8e168232c8110a6c45ce62078f63e2725c74ebd1a62ab0612c7d669767949a51849b25b7788158",
                16).toByteArray();
        byte[] bPubKeyEnc = new BigInteger(
                "308202283082011b06092a864886f70d0103013082010c0282010100d931d5890af0a4998888a74a4304d4ea4c20ab1b76f9531e5b3147e17f535f9f559a9bc8925bb4bc2968c415937ebae78cedb8a6af5617212d174f72fac275b375c31bdeb246aa04fdde6fb232ce867720faafdc01232e747596f5b5bd3b1de5724364a0c231d9010498df65790452e094b0dcd7064a31471fdacaa99ad54fab9c8696f65d0ce25e48b0cf19fa431588d4e9212cca0c040758f1b07730441adfdb4a219da5ffd77da61c35bb305549ce79b9abfc2e0864fcb6de8a91880b660437e410a2502119502d39f45666e3498e89e3f9f2a73b1d2f31c25de940120594f852ce586e9fc5b7784bcbd9bb6083ad79d218540cbb751983a2ec82b4e9c12b020102020204000382010500028201006af3f9d5c20dc5ecee9b2f394799074b6d445949f968c62e42f0e0970ccca78f1ca5cc087aa4d37f92ccc0e7cf11bd8da0d84c8be61b39a6c9941a402a324e239ddfb45bc88e3300a79ad2c4d8e09152d9b079e47f50932c6db8faf6b03cac40e79e1e5a050b8418f62b33e1829b9ebb9508dff34fc83055cf4ee49c331e001191ad6e5306975afa256603542c2d37ad6f506deaf794ea7fba0d7c11a2c253be2b45fddec064f8fa5f30f99c164a857598b5c43297623f8b8c7c5fabbf3b22ac0cf64aecf66d9fea299574ff372c0fcf3feaf6dc043d7b7e92069e7b51545004c99a6ff9d7cb993fba3186e053069821fe26131d45679f1e0f670f168fb46f83",
                16).toByteArray();


        KeyFactory aKeyFac = KeyFactory.getInstance("DH", providerNameX);
        X509EncodedKeySpec x509KeySpecForB = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpecForB);

        PrivateKey aPrivKey = aKeyFac.generatePrivate(new PKCS8EncodedKeySpec(aPrivKeyEnc));

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", providerNameX);
        aKeyAgree.init(aPrivKey);

        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */

        KeyFactory bKeyFac = KeyFactory.getInstance("DH", providerNameY);
        X509EncodedKeySpec x509KeySpecForA = new X509EncodedKeySpec(aPubKeyEnc);
        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpecForA);

        PrivateKey bPrivKey = bKeyFac.generatePrivate(new PKCS8EncodedKeySpec(bPrivKeyEnc));

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", providerNameY);
        bKeyAgree.init(bPrivKey);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        //

    }

    void test_dh_keyFactory(String providerNameX, String providerNameY) throws Exception {
        /*
         * A creates own DH key pair with 2048-bit key size
         */
        //final String methodName = "test_dh_keyFactory ";

        KeyPairGenerator aKpairGen = KeyPairGenerator.getInstance("DH", providerNameX);
        aKpairGen.initialize(2048);

        KeyPair aKpair = aKpairGen.generateKeyPair();

        // A creates and initializes A DH KeyAgreement object
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", providerNameX);
        aKeyAgree.init(aKpair.getPrivate());

        // A encodes A's public key, and sends it over to B.
        byte[] aPubKeyEnc = aKpair.getPublic().getEncoded();


        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */
        KeyFactory bKeyFac = KeyFactory.getInstance("DH", providerNameY);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(aPubKeyEnc);

        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpec);


        /*
         * B gets the DH parameters associated with A's public key.B must use the same
         * parameters when B generates B's own key pair.
         */
        DHParameterSpec dhParamFromAPubKey = ((DHPublicKey) aPubKey).getParams();

        KeyPairGenerator bKpairGen = KeyPairGenerator.getInstance("DH", providerNameY);
        bKpairGen.initialize(dhParamFromAPubKey);
        KeyPair bKpair = bKpairGen.generateKeyPair();

        // B creates and initializes DH KeyAgreement object

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", providerNameY);
        bKeyAgree.init(bKpair.getPrivate());

        // B encodes public key, and sends it over to A.
        byte[] bPubKeyEnc = bKpair.getPublic().getEncoded();


        /*
         * A uses B's public key for the first (and only) phase of A's version of the DH
         * protocol. Before A can do so, A has to instantiate a DH public key from B's
         * encoded key material.
         */
        KeyFactory aKeyFac = KeyFactory.getInstance("DH", providerNameX);
        x509KeySpec = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpec);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(aKpair.getPrivate().getEncoded()));
            System.out.println(
                    "KeyPairA.publicKey=" + BaseUtils.bytesToHex(aKpair.getPublic().getEncoded()));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(bKpair.getPrivate().getEncoded()));
            System.out.println(
                    "KeyPairB.publicKey=" + BaseUtils.bytesToHex(bKpair.getPublic().getEncoded()));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        /*
         * Now let's create a SecretKey object using the shared secret and use it for
         * encryption. First, we generate SecretKeys for the "AES" algorithm (based on
         * the raw shared secret data) and Then we use AES in CBC mode, which requires
         * an initialization vector (IV) parameter. Note that you have to use the same
         * IV for encryption and decryption: If you use a different IV for decryption
         * than you used for encryption, decryption will fail.
         *
         * If you do not specify an IV when you initialize the Cipher object for
         * encryption, the underlying implementation will generate a random one, which
         * you have to retrieve using the javax.crypto.Cipher.getParameters() method,
         * which returns an instance of java.security.AlgorithmParameters. You need to
         * transfer the contents of that object (e.g., in encoded format, obtained via
         * the AlgorithmParameters.getEncoded() method) to the party who will do the
         * decryption. When initializing the Cipher for decryption, the (reinstantiated)
         * AlgorithmParameters object must be explicitly passed to the Cipher.init()
         * method.
         */

        SecretKeySpec bAesKey = new SecretKeySpec(bSharedSecret, 0, 16, "AES");
        SecretKeySpec aAesKey = new SecretKeySpec(aSharedSecret, 0, 16, "AES");

        /*
         * B encrypts, using AES in CBC mode
         */
        Cipher bCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerNameX);
        bCipher.init(Cipher.ENCRYPT_MODE, bAesKey);
        byte[] cleartext = "This is just an example".getBytes();
        byte[] ciphertext = bCipher.doFinal(cleartext);

        // Retrieve the parameter that was used, and transfer it to A in
        // encoded format
        byte[] encodedParams = bCipher.getParameters().getEncoded();

        /*
         * A decrypts, using AES in CBC mode
         */

        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from B
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES", providerNameX);
        aesParams.init(encodedParams);
        Cipher aCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerNameX);
        aCipher.init(Cipher.DECRYPT_MODE, aAesKey, aesParams);
        byte[] recovered = aCipher.doFinal(ciphertext);
        if (!java.util.Arrays.equals(cleartext, recovered))
            throw new Exception("AES in CBC mode recovered text is " + "different from cleartext");
        System.out.println("AES in CBC mode recovered text is " + "same as cleartext");
    }

}
