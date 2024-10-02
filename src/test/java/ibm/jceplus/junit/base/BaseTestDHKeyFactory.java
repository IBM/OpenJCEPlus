/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
                "3082012102010030819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b0201020481830281806502b69705a45d97a848c97137c088a0dd7c6b4637481d6fc4cb7a70313aa1682302998c7bee0ec47408e73913656e67033385d26c54c599317071454ac96f4dcfb40ec58789353fe29e37f4b1ac567b10a037791d80b5139cab2b61746cafc0ebb7742c5fae86c1b8a3715854c2c3ce32b58ddd8cc4e387a3063382007edbb0",
                16).toByteArray();


        byte[] aPubKeyEnc = new BigInteger(
                "3082011f30819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b02010203818400028180008f223ec76dcf711abfd5693268780a920d9e2d350ba8f11acb0caaa5019cf3c8ad69343fe8f16b81874961e4b6512d3e60a78864619e99f7da3e9811661c4f25b80f8a70f9ddaa79d4bbf1ed0491df02b4f0517490a60af2b80fb5db8355dab9ef06718c89c7eda124ef61ab0dda0de682f50ff22b605cc2ba2e3f0b96803b",
                16).toByteArray();

        byte[] bPrivKeyEnc = new BigInteger(
                "3082012102010030819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b0201020481830281804cd3001b1c93f247412f5594f9d20a7125f2055981a48c5115a80414db882d41547143d487ed14eb06b44a71db6094196288872fa651c94d9aa0b0abcc5861927ecb63d747ebffd97b68bf0cb9df6e443e36f7b737154c4d2c27fda65311f1e66f88817377249ac5c19e76b0100b753e58ead682b4fd995d4b5b6609fbd370ce",
                16).toByteArray();

        byte[] bPubKeyEnc = new BigInteger(
                "3082011f30819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b020102038184000281806903be9046b2b24127614f97584ad70a6ca6c5e39b9979b7f95729c6b86803719d4677e5758add0c5c8b936446795ef3af67922323f00cc1b488cdddf28f13d75452451853cb1c84a9ae701ec2664b27d91e9b74b381e0957cb638a5c5c0acf85c297d29417f8917b2ea091da2766919dfb2e490253259d2b117e9c616d14b58",
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
