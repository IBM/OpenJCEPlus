/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sun.security.util.KeyUtil;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestDHKeyPairGenerator extends BaseTestJunit5 {

    private static final BigInteger p_1024 = new BigInteger(
        "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",
        16);

    private static final BigInteger g_1024 = new BigInteger(
        "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",
        16);

    private static final BigInteger p_2048 = new BigInteger(
        "24411209893452987982292764298214666563244502108061332429386640762028613944128160958895651358369340617913723942648980595662900397364654037992477306346975555070731906211991330607572500092846972550669206248817906971178489109618091786420639402573006669894740449806296627656350692199924647254064170619723090086490863047112010159257790253286951285397621794370492477371659895119712649029073020971899481274886979229883486313718228936740160705239157339084673807557507596909526771665732158004755500890957481963807104507454286192846294557895603003106614304345189884618591002156946923803100585097553740787441936978505629483919483");

    private static BigInteger g_2048 = new BigInteger("2");

    private static BigInteger p_3072 = new BigInteger(
        "3984726680996695938962530783543770621997197473797019619492946402463918417974497449270696748883559745014593242225907774697640386789896248706335921624183539227205861406166856041746789956216934423396757374206025238856202293838352862734099515200718875434405427369719603585129497078302914334772902691929376427249954866774998298703463206134964046896733427732673256972486928489840823651681900010770058336600542645764047577763395592081876921743345250127718495033142581430701445402164649747669576965600224735364308288544169046144177941654736483051957076428125812797541358982286057794581533902184510411947880873120004751553586672451616979739170365048511131190463723874572607671672034164712408726027133496561307635238731744151197657342092428256720849422853680865099763220950179379320414708442398940768246727677052983689792890777633870538229105994448668684028184541713919676808045449847221960856377983311349436917256827988839394245521963");

    private static BigInteger g_3072 = new BigInteger("2");
    private static BigInteger p_4096 = new BigInteger("00bffcbc796f5f5abc038bd0f5425b" + "434c9c841b61aeada4babb733fed0f"
        + "4862c892f9eb0d18f63c6543b0dd90" + "53be2067414803e5f88ff10b2af5ae"
        + "7a3a91b888a918f32699af4d5649fb" + "11056954620bd3eac082c975934368"
        + "6f51ffebadc5ed6f01bfe3ad17418a" + "a167b8ce539bd8793b8cbce1b552ce"
        + "1c19067fd79f3ca6ec43ded82da84f" + "06dc26baac741f74518ca7bde76c5e"
        + "9767bbfd2548cf90ca7e928905c8df" + "1a15462d58ba539f1d37050ef77559"
        + "5226ddb42aa900481560e4419c0719" + "b73927417d7c1f9db30edb1421a77c"
        + "b4e8b46e7d8fb40df64efbb29e7fb0" + "ef163a59cf33b8a9e21979cc383842"
        + "2057a46e64679e48edafcd014dd464" + "4abd26350bb6cc35daea22d43e70ef"
        + "6564630f2cfd9261bd64c346afb3e0" + "8533b67c5702d9edb14cd695bd490e"
        + "f4db1fce0fabaa78b8f0248b44098f" + "f1bf21b4ade769bbe25e8a39eb0ea9"
        + "b974e3630af226807efce8dce15353" + "d79bdb30656585dd556778e27cbdc1"
        + "d1f60c33560e4c80ff39249c6bcc16" + "675fc6a1c228821e45bbb1b0fcaa98"
        + "c8f84b6340bfa9282c03bc66566fa3" + "8e82d8fee481f02ea5b5f5742f8aca"
        + "4aa4aad1ade687dbded4ec0dfa6856" + "7bcc4dbe009e4384b7762d38cbcf07"
        + "36626dcac6b27470642225c4414966" + "24de3d44edf55ae7dc58c30aded35e"
        + "dcc4eff89494948f20946a2f0dddcd" + "c0edf952e63a6c7597b8a2627c7054" + "ae644b",
        16);
    private static BigInteger g_4096 = new BigInteger("5", 16);
    private static BigInteger p_6144 = new BigInteger("00ee44c7210997bc150de5179bdd70" + "11f9cb032d8c2d6ffda5d45f9e7166"
        + "004aa8d30581405454c7cbb84ba39b" + "864513c1c388b89956d3191613036b"
        + "825620d5048c53f09374cd00484c07" + "41871961998169d1d7b87f11714d84"
        + "222649e1d7f5c1e9a1c98313958dc6" + "9cf3a0197c71369e0193c62b70c526"
        + "22e01e6c1d14f054de505910cbe594" + "0d69698dfd08afad4b2c3da06d5e06"
        + "8f1d96e29d17f6ada88f5339783648" + "bd43ca19edf33a59d3bfaa47743372"
        + "b315c858da5c5c4a4015fbac013b1c" + "f250812a35c80676ac289435659cb3"
        + "f8f7e7380e86e634303977c5ac331e" + "390798043e25921890e5b10b9c7a82"
        + "020b7b5a29a7105c1640e3f635ed01" + "aed002f6d6d6258ce874dbeaf8129d"
        + "dd50086607f54d552e3c9da4a935c6" + "b715776c0b97cc8e249546bcd39110"
        + "49877f5521d78cddb177819c96f529" + "61129ed5c6d948f68a14aa68231b11"
        + "aaedea491e42f17986f4524273193e" + "d68c03d3c5b7f83ccfc28eb3f0bc88"
        + "7df84a02dbb0e847ec52558b72c293" + "27010440859026a6c7de02a309edcb"
        + "dfc452c7167c3af97974a59e4e279f" + "bf23e6378eb476d0588c48f69431a9"
        + "339b4eba9df0725c7fec44ee0cea71" + "d0143246f982721a4aba325a7da1e9"
        + "85f888a43243582c6bc0707c0ff950" + "20a72f177a5207d59d7cc15f430f38"
        + "ec45f6ac502d7a81ab016cc6128a3d" + "3c7bc9ad830f60529eb2aee98b58e1"
        + "f2a913d63339b818fcb5e325cc90ba" + "fa51cf73e3137a59aaec368dc69bc3"
        + "302acac0351ebf39e14d93e97353ac" + "f808a87121a088e2c97f85c4aa5d61"
        + "ab6d4e33f7f88ec8b4ea4fbb9158a8" + "48142f105357b72869174e3de18bcb"
        + "9dd368ce988a0092ca93821a3bdf87" + "fad0761de3f5f3d2e349a67c6fe85a"
        + "89681300c4ee2d8b21f8bf2b426f9c" + "31dde2348c5bcef0a5008fcdb4c234"
        + "363e3c91e506e574e5fc35474ae749" + "0ea304020ea96732aa9d2b6c668728"
        + "318a836ad53e30426968a0245fdcd8" + "a797ed7a3e48b4976c580c379b1d9e"
        + "d7155ed864200877667f3e81c0e3e0" + "97038d27a12d71671e8b04689a4ec7"
        + "6eabfe4e8607a2575d1bd3d1cb4fd7" + "7e3d4b8b", 16);
    private static BigInteger g_6144 = new BigInteger("5", 16);
    private static BigInteger p_8192 = new BigInteger("00c164c46dbb0596c77938a260999a" + "bfec25cc6368e789f1483891784d35"
        + "09707426319aa5c5d66361a29f4cb0" + "cf8abaf32c81f08b3edf1d599ca15d"
        + "4a11d95cedaa7ec3b9677bc28ef9aa" + "86d6b9a5d7f425d0d5243ba2afb67a"
        + "c94a1007729d9e053d41c7ef5e0e4c" + "ec815c1a98a0ed5860f0b99dea9d40"
        + "9afb4825f58b54e5865ae17c6e20de" + "5e2d9b45bc916ebaba157a0f5b6ddb"
        + "e5aca5e9461f42afc7001bd73d2933" + "cff1e6efed2265ecbe16c5586dc7e4"
        + "db9fe5d760047b1bcee97ca7b06e58" + "46ee5f197fa862a53dd05565903fc6"
        + "2ea87156a9cefafabbeacc13e017c6" + "a71097379d3ed83e56d45b17221455"
        + "a6e11ad3e8e1032d87d572471c93ad" + "504d67ffd55ea4586b966b7389cc8b"
        + "16e535e6ca822244fb293cc7100627" + "67bf19607c46dde5926b0100c479fc"
        + "5731177a309d84a46d8dabc50d5b8a" + "3c26f1316edb6cbddc28acb2f25560"
        + "1f292b5f6bb2dc5e3f4a9b7cc44a93" + "dbd775b4559eea91c89ca232e60590"
        + "c5b54c1bcc9037542f38ef0c1109fd" + "c6a684f64cb958b9fba757a1717d03"
        + "40dec22dc8b77ee853d2272ddbf7c9" + "dfe11a776d20bf117c7eab2bf0ec7b"
        + "f208f1ad359c0eb85658796471f863" + "1584fc3f68f647a1064aa4dafa08f9"
        + "754739840bc6ba016544c963fda63d" + "97b8a0b50c30bfccf2180bf18a4cbe"
        + "708cae982f2fbcb39341a7f2f90aa0" + "2fceb0c795393a2e9eadb54a206db6"
        + "862442627a17897c30ac2e33a6135e" + "6816f2aed8e692ed4b5012d8f4e696"
        + "916f2c82c1719190c284146b6c794d" + "a617c52da1a63a303c5dfa8afa93e4"
        + "beaadab0b121be4812e5b5ffbae09c" + "1c8ffde32707908aa7b7361cd76d9e"
        + "aaf095fb91e5b2300f2e87eaa71c49" + "1ca25d3cfdcd259e60ffceca650aa5"
        + "41aec8fac6dc5d05d9c3189ec59e27" + "292e02d4a67aba7e895a110e0fb62e"
        + "cfee6492cb5e9bd4fe579abfdcd5a0" + "c5da48d93213e7002579922741ab2b"
        + "283b459fd949da212b723392a3e1dd" + "b62ae23d42d9c6a49d7fe84046e3f5"
        + "b808a900bb8e52f358823e9eec31fc" + "986ee2ad8b0bdf4234a818e1dbad0b"
        + "95d38b0789340b531f403580435659" + "6f1c386c6853b78cbf7f7d745013b9"
        + "07e5c24af35b81b69c5cdc674a06e1" + "ac3a728e09b00a9ac9e788ace68b6a"
        + "4a556598e410666bc29357188faeb3" + "8be56e5691c17ab72163910fe7f9d0"
        + "1f8c8468bdf6ba9845a2873b0339c1" + "855263a59abded562b1f40efd49b81"
        + "fac9d7f5054be04e51ca0055ff1360" + "f6dc66b8886b5f9b2389e36b9213aa"
        + "01e33cba2ac337592b986a436d0e05" + "58521c1d6e9a173bf66c4742bc8ba5"
        + "91390032f5a3e9a0a25b5035c0f0f9" + "94869436b37853bf8400a1f435b61a"
        + "ba3be39c3c6b2936aff805a2fe0797" + "16fd71be634f8ff90018a68b5aaeb8"
        + "2d6cfe1bb6f0e577e38d3364ea0aa8" + "a1ad165aa95c6de0d4a079eda2898a"
        + "9cd76f45e3", 16);
    private static BigInteger g_8192 = new BigInteger("5", 16);

    KeyPairGenerator kpg = null;
    DHParameterSpec dhParams_1024 = null;
    DHParameterSpec dhParams_2048 = null;
    DHParameterSpec dhParams_3072 = null;
    DHParameterSpec dhParams_4096 = null;
    DHParameterSpec dhParams_6144 = null;
    DHParameterSpec dhParams_8192 = null;

    public static final String PROVIDER_OPENJCEPlus = "OpenJCEPlus";
    public static final String PROVIDER_OPENJCEPlusFIPS = "OpenJCEPlusFIPS";

    @BeforeEach
    public void setUp() throws Exception {
        kpg = KeyPairGenerator.getInstance("DH", getProviderName());
        dhParams_1024 = new DHParameterSpec(p_1024, g_1024);
        dhParams_2048 = new DHParameterSpec(p_2048, g_2048);
        dhParams_3072 = new DHParameterSpec(p_3072, g_3072);
        dhParams_4096 = new DHParameterSpec(p_4096, g_4096);
        dhParams_6144 = new DHParameterSpec(p_6144, g_6144);
        dhParams_8192 = new DHParameterSpec(p_8192, g_8192);
    }

    @Test
    public void testDHKeyGen_1024_withParams() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 1024 bit keys
            return;
        }
        kpg.initialize(dhParams_1024);
        compPrivPubKeyParams();

    }

    @Test
    public void testDHKeyGen_2048_withParams() throws Exception {
        kpg.initialize(dhParams_2048);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_3072_withParams() throws Exception {
        kpg.initialize(dhParams_3072);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_4096_withParams() throws Exception {
        kpg.initialize(dhParams_4096);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_6144_withParams() throws Exception {
        kpg.initialize(dhParams_6144);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_8192_withParams() throws Exception {
        kpg.initialize(dhParams_8192);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 1024 bit keys
            return;
        }
        kpg.initialize(1024);

        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_2048() throws Exception {
        kpg.initialize(2048);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_3072() throws Exception {
        kpg.initialize(3072);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_4096() throws Exception {
        kpg.initialize(4096);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_6144() throws Exception {
        kpg.initialize(6144);
        compPrivPubKeyParams();
    }

    @Test
    public void testDHKeyGen_8192() throws Exception {
        kpg.initialize(8192);
        compPrivPubKeyParams();
    }

    @Test
    public void testDefaultDHPrivateExpSize() throws Exception {
        //        int[] keypairSizes = { 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192 };
        int[] keypairSizes = {2048, 3072, 4096, 6144, 8192};
        System.out.println("Testing provider: " + getProviderName() + " DH private exponenent size");

        for (int keypairSize : keypairSizes) {
            //System.out.println("\n**********Keysize: " + keypairSize);
            int expectedLSize = getDefDHPrivateExpSize(keypairSize);
            System.out.print("\tkeypair size: " + keypairSize + " ");

            try {
                kpg.initialize(keypairSize);
                DHParameterSpec spec = generateAndCheck(keypairSize, expectedLSize);
                System.out.print(" default parameters good.");

                // now use a custom lSize and see if it gets used
                expectedLSize += 2;
                DHParameterSpec spec2 = new DHParameterSpec(spec.getP(), spec.getG(),
                        expectedLSize);
                kpg.initialize(spec2);
                generateAndCheck(keypairSize, expectedLSize);
                System.out.print(" Custom parameters good.");

            } catch (InvalidParameterException invalidParameterException) {
                if ((PROVIDER_OPENJCEPlusFIPS.equalsIgnoreCase(getProviderName())
                        || PROVIDER_OPENJCEPlus.equalsIgnoreCase(getProviderName()))
                        && (keypairSize == 1536)) {
                    System.out.print("Keysize 1536 not supported on provider: " + getProviderName()
                            + "<===Expected exception caught");
                } else {
                    invalidParameterException.printStackTrace();
                    //throw invalidParameterException;
                    fail();
                }

            } finally {
                System.out.println("");
            }
        }
    }

    /*
     * Taken from OSB attachments SecurityProviderConstants.java
     */
    private static final int getDefDHPrivateExpSize(int dhGroupSize) {
        // System.out.println("Hack for Oracle JDK from
        // SecurityProviderConstants.java");
        // use 2*security strength as default private exponent size
        // as in table 2 of NIST SP 800-57 part 1 rev 5, sec 5.6.1.1
        // and table 25 of NIST SP 800-56A rev 3, appendix D.
        if (dhGroupSize >= 15360) {
            return 512;
        } else if (dhGroupSize >= 8192) {
            return 400;
        } else if (dhGroupSize >= 7680) {
            return 384;
        } else if (dhGroupSize >= 6144) {
            return 352;
        } else if (dhGroupSize >= 4096) {
            return 304;
        } else if (dhGroupSize >= 3072) {
            return 256;
        } else if (dhGroupSize >= 2048) {
            return 224;
        } else {
            // min value for legacy key sizes
            return 160;
        }
    }

    /**
     * generate the DH keypair
     * assert keypair size generated equals the expectedKeySize
     * assert that the private key exponent bit length is greater than or equal to the expectedprivate key exponent bit length 
     *
     * @param expectedKeySize
     * @param expectedMinimumPrivateKeyExponentBitLength
     * @return DHParameterSpec from generated private key
     */
    private DHParameterSpec generateAndCheck(int expectedKeySize,
            int expectedMinimumPrivateKeyExponentBitLength) {

        //System.out.println("Testing ks = " + expKeySize + " w/ lSize = " + expLSize);
        KeyPair kp = kpg.generateKeyPair();
        DHParameterSpec generatedDhPrivateKeyParams = ((DHKey) kp.getPrivate()).getParams();

        // if ((generated.getP().bitLength() != expKeySize) || (generated.getL() != expLSize))  original osb code used equality test not greater than or equal
        assertTrue(((generatedDhPrivateKeyParams.getP().bitLength() == expectedKeySize) &&
                    (generatedDhPrivateKeyParams.getL() >= expectedMinimumPrivateKeyExponentBitLength)),
                "Error: size check failed, got " + generatedDhPrivateKeyParams.getP().bitLength()
                        + " and " + generatedDhPrivateKeyParams.getL());

        return generatedDhPrivateKeyParams;
    }

    private void compPrivPubKeyParams() {
        KeyPair kp = kpg.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        DHPublicKey dhpu = (DHPublicKey) kp.getPublic();
        DHPrivateKey dhpr = (DHPrivateKey) kp.getPrivate();

        assert (dhpu.getY() != null);
        assert (dhpr.getX() != null);

        assert (dhpu.getParams().getP().compareTo(dhpr.getParams().getP()) == 0);
        assert (dhpu.getParams().getG().compareTo(dhpr.getParams().getG()) == 0);

        BigInteger p = dhpu.getParams().getP();
        BigInteger left = BigInteger.ONE;
        BigInteger right = p.subtract(BigInteger.ONE);
        BigInteger x = dhpr.getX();
        assertFalse(((x.compareTo(left) <= 0) || (x.compareTo(right) >= 0)), "Private exponent X outside range [2, p - 2]: x: " + x + " p: " + p);

        BigInteger y = dhpu.getY();
        assertFalse(((y.compareTo(left) <= 0) || (y.compareTo(right) >= 0)), "Public exponent Y outside range [2, p - 2]: x: " + x + " p: " + p);

        //Exponent bit length does not have to be the exact same but private should be at least 1/2 of keysize
        //OpenJCEPlus will generate a private key with exponent bit length of keysize - 1
        @SuppressWarnings("restriction")
        int keysize = KeyUtil.getKeySize(dhpu);
        int minimumPrivateExponentBitLength = keysize - 1;
        assertTrue(dhpr.getParams().getL() >= minimumPrivateExponentBitLength,
                "Minimum exponent bit length: " + minimumPrivateExponentBitLength + " not met by: "
                        + dhpr.getParams().getL() + " for DH keysize: " + keysize);

        //the key parameter exponent length equality test was removed and replaced by the minimum exponent test above
        //        assertEquals("Invalid public key exponent bit length" , dhpu.getParams().getL(), dhpr.getParams().getL());
        //        assert(dhpu.getParams().getL() == dhpr.getParams().getL());
    }

    /*
     * Test that invalid keypair sizes are rejected.
     * Note: the keypair size may actually be able to be supported by underlying crypto but is rejected at 
     * KeyPairGenerator initialize time.
     * Similar checks on keypair size may be found in other DH related classes as well.  
     */
    @Test
    public void testInvalidDHKeySize() throws Exception {
        int[] someJCEPlusInvalidKeypairSizes = {1088, 1280, 1536, 1728, 2944, 3008, 3968, 4992,
                5952, 6976, 7936};

        System.out.println("Testing invalid keypair sizes with provider: " + getProviderName());
        int[] keypairSizes = someJCEPlusInvalidKeypairSizes;

        for (int keypairSize : keypairSizes) {
            System.out.print("\tkeypair size: " + keypairSize);

            try {
                kpg.initialize(keypairSize);

                fail("Invalid DH keypair size: " + keypairSize + " did not cause with provider: "
                        + getProviderName());
            } catch (InvalidParameterException invalidParameterException) {
                System.out.print(" Keysize: (" + keypairSize + ") not supported on provider: "
                        + getProviderName() + "<===Expected InvalidParameterException caught");
            } finally {
                System.out.println("");
            }
        }
    }

}


