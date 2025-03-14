/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.ChaCha20Constants;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class BaseTestChaCha20NoReuse extends BaseTestCipher implements ChaCha20Constants {

    private static final String ALG_CC20 = "ChaCha20";
    private static final String ALG_CC20_P1305 = "ChaCha20-Poly1305";

    /**
     * Basic TestMethod interface definition.
     */
    public interface TestMethod {
        /**
         * Runs the actual test case
         *
         * @param algorithm the algorithm to use (e.g. ChaCha20, etc.)
         *
         * @return true if the test passes, false otherwise.
         */
        boolean run(String algorithm, String providerName);

        /**
         * Check if this TestMethod can be run for this algorithm. Some tests are
         * specific to ChaCha20 or ChaCha20-Poly1305, so this method can be used to
         * determine if a given Cipher type is appropriate.
         *
         * @param algorithm the algorithm to use.
         *
         * @return true if this test can be run on this algorithm, false otherwise.
         */
        boolean isValid(String algorithm);

        String getName();
    }

    public static class TestData {
        public TestData(String name, String keyStr, String nonceStr, int ctr, int dir,
                String inputStr, String aadStr, String outStr) {
            testName = Objects.requireNonNull(name);
            key = BaseUtils.hexStringToByteArray(Objects.requireNonNull(keyStr));
            nonce = BaseUtils.hexStringToByteArray(Objects.requireNonNull(nonceStr));
            if ((counter = ctr) < 0) {
                throw new IllegalArgumentException("counter must be 0 or greater");
            }
            direction = dir;
            if ((direction != Cipher.ENCRYPT_MODE) && (direction != Cipher.DECRYPT_MODE)) {
                throw new IllegalArgumentException(
                        "Direction must be ENCRYPT_MODE or DECRYPT_MODE");
            }
            input = BaseUtils.hexStringToByteArray(Objects.requireNonNull(inputStr));
            aad = (aadStr != null) ? BaseUtils.hexStringToByteArray(aadStr) : null;
            expOutput = BaseUtils.hexStringToByteArray(Objects.requireNonNull(outStr));
        }

        public final String testName;
        public final byte[] key;
        public final byte[] nonce;
        public final int counter;
        public final int direction;
        public final byte[] input;
        public final byte[] aad;
        public final byte[] expOutput;
    }

    public static final List<TestData> testList = new LinkedList<TestData>() {
        {
            add(new TestData("RFC 7539 Sample Test Vector [ENCRYPT]",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "000000000000004a00000000", 1, Cipher.ENCRYPT_MODE,
                    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
                            + "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
                            + "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                            + "637265656e20776f756c642062652069742e",
                    null,
                    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                            + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                            + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                            + "5af90bbf74a35be6b40b8eedf2785e42874d"));
            add(new TestData("RFC 7539 Sample Test Vector [DECRYPT]",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "000000000000004a00000000", 1, Cipher.DECRYPT_MODE,
                    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                            + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                            + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                            + "5af90bbf74a35be6b40b8eedf2785e42874d",
                    null,
                    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
                            + "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
                            + "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                            + "637265656e20776f756c642062652069742e"));
        }
    };

    public static final List<TestData> aeadTestList = new LinkedList<TestData>() {
        {
            add(new TestData("RFC 7539 Sample AEAD Test Vector",
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                    "070000004041424344454647", 1, Cipher.ENCRYPT_MODE,
                    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
                            + "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
                            + "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                            + "637265656e20776f756c642062652069742e",
                    "50515253c0c1c2c3c4c5c6c7",
                    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                            + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                            + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                            + "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060"
                            + "0691"));
            add(new TestData("RFC 7539 A.5 Sample Decryption",
                    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                    "000000000102030405060708", 1, Cipher.DECRYPT_MODE,
                    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
                            + "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
                            + "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
                            + "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
                            + "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
                            + "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
                            + "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
                            + "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
                            + "a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38",
                    "f33388860000000000004e91",
                    "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
                            + "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
                            + "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
                            + "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
                            + "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
                            + "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
                            + "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
                            + "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
                            + "726573732e2fe2809d"));
        }
    };

    /**
     * Make sure we do not use this Cipher object without initializing it at all
     */
    public final TestMethod noInitTest = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return true; // Valid for all algs
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out.println("----- No Init Test noInitTest [" + algorithm + "] -----");
            try {
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());
                TestData testData;
                switch (algorithm) {
                    case ALG_CC20:
                        testData = testList.get(0);
                        break;
                    case ALG_CC20_P1305:
                        testData = aeadTestList.get(0);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported cipher type: " + algorithm);
                }

                // Attempting to use the cipher without initializing it
                // should throw an IllegalStateException
                try {
                    if (algorithm.equals(ALG_CC20_P1305)) {
                        cipher.updateAAD(testData.aad);
                    }
                    cipher.doFinal(testData.input);
                    throw new RuntimeException("Expected IllegalStateException not thrown");
                } catch (IllegalStateException ise) {
                    // Do nothing, this is what we expected to happen
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "No Init Test noInitTest";
        }
    };

    /**
     * Make sure we don't allow a double init using the same parameters
     */
    public final TestMethod doubleInitTest = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return true; // Valid for all algs
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out.println("----- Double Init Test doubleInitTest [" + algorithm + "] -----");
            try {
                AlgorithmParameterSpec spec;
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());
                TestData testData;
                switch (algorithm) {
                    case ALG_CC20:
                        testData = testList.get(0);
                        spec = new ChaCha20ParameterSpec(testData.nonce, testData.counter);
                        break;
                    case ALG_CC20_P1305:
                        testData = aeadTestList.get(0);
                        spec = new IvParameterSpec(testData.nonce);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported cipher type: " + algorithm);
                }
                SecretKey key = new SecretKeySpec(testData.key, ALG_CC20);

                // Initialize the first time, this should work.
                cipher.init(testData.direction, key, spec);

                // Immediately initializing a second time with the same
                // parameters should fail
                try {
                    cipher.init(testData.direction, key, spec);
                    throw new RuntimeException("Expected InvalidKeyException not thrown");
                } catch (InvalidKeyException ike) {
                    // Do nothing, this is what we expected to happen
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "Double Init Test doubleInitTest";
        }
    };

    /**
     * Attempt to run two full encryption operations without an init in between.
     */
    public final TestMethod encTwiceNoInit = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return true; // Valid for all algs
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out.println("----- Encrypt second time without init encTwiceNoInit [" + algorithm
                    + "] -----");
            try {
                AlgorithmParameterSpec spec;
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());
                TestData testData;
                switch (algorithm) {
                    case ALG_CC20:
                        testData = testList.get(0);
                        spec = new ChaCha20ParameterSpec(testData.nonce, testData.counter);
                        break;
                    case ALG_CC20_P1305:
                        testData = aeadTestList.get(0);
                        spec = new IvParameterSpec(testData.nonce);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported cipher type: " + algorithm);
                }
                SecretKey key = new SecretKeySpec(testData.key, ALG_CC20);

                // Initialize and encrypt
                cipher.init(testData.direction, key, spec);
                if (algorithm.equals(ALG_CC20_P1305)) {
                    cipher.updateAAD(testData.aad);
                }
                cipher.doFinal(testData.input);
                System.out.println("First encryption complete");

                // Now attempt to encrypt again without changing the key/IV
                // This should fail.
                try {
                    if (algorithm.equals(ALG_CC20_P1305)) {
                        cipher.updateAAD(testData.aad);
                    }
                    cipher.doFinal(testData.input);
                    throw new RuntimeException("Expected IllegalStateException not thrown");
                } catch (IllegalStateException ise) {
                    // Do nothing, this is what we expected to happen
                    System.out.println("Expected IllegalStateException= " + ise.getMessage());
                    // ise.printStackTrace();
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "Encrypt second time without init encTwiceNoInit";
        }
    };

    /**
     * Attempt to run two full decryption operations without an init in between.
     */
    public final TestMethod decTwiceNoInit = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return true; // Valid for all algs
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out.println("----- Decrypt second time without init decTwiceNoInit [" + algorithm
                    + "] -----");
            try {
                AlgorithmParameterSpec spec;
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());
                TestData testData;
                switch (algorithm) {
                    case ALG_CC20:
                        testData = testList.get(1);
                        spec = new ChaCha20ParameterSpec(testData.nonce, testData.counter);
                        break;
                    case ALG_CC20_P1305:
                        testData = aeadTestList.get(1);
                        spec = new IvParameterSpec(testData.nonce);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported cipher type: " + algorithm);
                }
                SecretKey key = new SecretKeySpec(testData.key, ALG_CC20);

                // Initialize and encrypt
                cipher.init(testData.direction, key, spec);
                if (algorithm.equals(ALG_CC20_P1305)) {
                    cipher.updateAAD(testData.aad);
                }
                cipher.doFinal(testData.input);
                System.out.println("First decryption complete");

                // Now attempt to encrypt again without changing the key/IV
                // This should fail.
                try {
                    if (algorithm.equals(ALG_CC20_P1305)) {
                        cipher.updateAAD(testData.aad);
                    }
                    cipher.doFinal(testData.input);
                    if (testData.direction == Cipher.ENCRYPT_MODE) {
                        throw new RuntimeException("Expected IllegalStateException not thrown");
                    }
                } catch (IllegalStateException ise) {
                    ise.printStackTrace();
                    if (testData.direction == Cipher.DECRYPT_MODE) {
                        throw new RuntimeException("Unexpected IllegalStateException thrown");
                    }
                    // Do nothing, this is what we expected to happen for encryption
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "Decrypt second time without init decTwiceNoInit";
        }
    };

    /**
     * Perform an AEAD decryption with corrupted data so the tag does not match.
     * Then attempt to reuse the cipher without initialization.
     */
    public final TestMethod decFailNoInit = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return algorithm.equals(ALG_CC20_P1305);
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out.println("----- Fail decryption, try again with no init decFailNoInit ["
                    + algorithm + "] -----");
            try {
                TestData testData = aeadTestList.get(1);
                AlgorithmParameterSpec spec = new IvParameterSpec(testData.nonce);
                byte[] corruptInput = testData.input.clone();
                corruptInput[0]++; // Corrupt the ciphertext
                SecretKey key = new SecretKeySpec(testData.key, ALG_CC20);
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());

                try {
                    // Initialize and encrypt
                    cipher.init(testData.direction, key, spec);
                    cipher.updateAAD(testData.aad);
                    cipher.doFinal(corruptInput);
                    throw new RuntimeException("Expected AEADBadTagException not thrown");
                } catch (AEADBadTagException abte) {
                    System.out.println("Expected decryption failure occurred");
                }

                // Make sure that despite the exception, the Cipher object is
                // not in a state that would leave it initialized and able
                // to process future decryption operations without init.
                try {
                    cipher.updateAAD(testData.aad);
                    cipher.doFinal(testData.input);
                } catch (IllegalStateException ise) {
                    // Do nothing, this is what we expected to happen
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "Fail decryption, try again with no init decFailNoInit";
        }
    };

    /**
     * Encrypt once successfully, then attempt to init with the same key and nonce.
     */
    public final TestMethod encTwiceInitSameParams = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return true; // Valid for all algs
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out
                    .println("----- Encrypt, then init with same params [" + algorithm + "] -----");
            try {
                AlgorithmParameterSpec spec;
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());
                TestData testData;
                switch (algorithm) {
                    case ALG_CC20:
                        testData = testList.get(0);
                        spec = new ChaCha20ParameterSpec(testData.nonce, testData.counter);
                        break;
                    case ALG_CC20_P1305:
                        testData = aeadTestList.get(0);
                        spec = new IvParameterSpec(testData.nonce);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported cipher type: " + algorithm);
                }
                SecretKey key = new SecretKeySpec(testData.key, ALG_CC20);

                // Initialize then encrypt
                cipher.init(testData.direction, key, spec);
                if (algorithm.equals(ALG_CC20_P1305)) {
                    cipher.updateAAD(testData.aad);
                }
                cipher.doFinal(testData.input);
                System.out.println("First encryption complete");

                // Initializing after the completed encryption with
                // the same key and nonce should fail.
                try {
                    cipher.init(testData.direction, key, spec);
                    if (testData.direction == Cipher.ENCRYPT_MODE) {
                        throw new RuntimeException("Expected InvalidKeyException not thrown");
                    }
                    throw new RuntimeException("Expected InvalidKeyException not thrown");
                } catch (InvalidKeyException ike) {
                    if (testData.direction == Cipher.DECRYPT_MODE) {
                        throw new RuntimeException("Unexpected InvalidKeyException thrown");
                    }
                    // Do nothing, this is what we expected to happen
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "Encrypt, then init with same params";
        }
    };

    /**
     * Decrypt once successfully, then attempt to init with the same key and nonce.
     */
    public final TestMethod decTwiceInitSameParams = new TestMethod() {
        @Override
        public boolean isValid(String algorithm) {
            return true; // Valid for all algs
        }

        @Override
        public boolean run(String algorithm, String providerName) {
            System.out.println("----- Decrypt, then init with same params decTwiceInitSameParams ["
                    + algorithm + "] -----");
            try {
                AlgorithmParameterSpec spec;
                Cipher cipher = Cipher.getInstance(algorithm, getProviderName());
                TestData testData;
                switch (algorithm) {
                    case ALG_CC20:
                        testData = testList.get(1);
                        spec = new ChaCha20ParameterSpec(testData.nonce, testData.counter);
                        break;
                    case ALG_CC20_P1305:
                        testData = aeadTestList.get(1);
                        spec = new IvParameterSpec(testData.nonce);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported cipher type: " + algorithm);
                }
                SecretKey key = new SecretKeySpec(testData.key, ALG_CC20);

                // Initialize then decrypt
                cipher.init(testData.direction, key, spec);
                if (algorithm.equals(ALG_CC20_P1305)) {
                    cipher.updateAAD(testData.aad);
                }
                cipher.doFinal(testData.input);
                System.out.println("First decryption complete");

                // Initializing after the completed decryption with
                // the same key and nonce - For decryption it should be OK since we are not generating IVs.
                try {
                    cipher.init(testData.direction, key, spec);
                    if (testData.direction == Cipher.ENCRYPT_MODE) {
                        throw new RuntimeException("Expected InvalidKeyException not thrown");
                    }
                    // Do nothing, this is what we expected to happen
                } catch (InvalidKeyException ike) {
                    if (testData.direction == Cipher.DECRYPT_MODE) {
                        throw new RuntimeException("Unexpected InvalidKeyException thrown");
                    }
                }
            } catch (Exception exc) {
                System.out.println("Unexpected exception: " + exc);
                exc.printStackTrace();
                return false;
            }

            return true;
        }

        @Override
        public String getName() {
            return "Decrypt, then init with same params decTwiceInitSameParams";
        }
    };

    public static final List<String> algList = Arrays.asList(ALG_CC20, ALG_CC20_P1305);

    public final List<TestMethod> testMethodList = Arrays.asList(noInitTest, doubleInitTest,
            encTwiceNoInit, decTwiceNoInit, decFailNoInit, encTwiceInitSameParams,
            decTwiceInitSameParams);

    //    public static final List<String> algList = Arrays.asList(ALG_CC20_P1305);                //DEBUG ONLY
    //    public static final List<TestMethod> testMethodList = Arrays.asList(decFailNoInit);    //DEBUG ONLY
    @Test
    public void testChaChaNoReuse() throws Exception {
        {
            int testsPassed = 0;
            int testNumber = 0;

            for (TestMethod tm : testMethodList) {
                System.out.println("\n");
                for (String alg : algList) {
                    if (tm.isValid(alg)) {
                        testNumber++;
                        boolean result = tm.run(alg, getProviderName());
                        System.out.println(tm.getName() + "[" + alg + "] Result: "
                                + (result ? "PASS" : "FAIL"));
                        System.out.println(
                                "==================================================================================");
                        if (result) {
                            testsPassed++;
                        }
                    }
                }
            }

            System.out.println("Total Tests: " + testNumber + ", Tests passed: " + testsPassed);
            if (testsPassed < testNumber) {
                throw new RuntimeException("Not all tests passed.  See output for failure info");
            }
        }
    }

}
