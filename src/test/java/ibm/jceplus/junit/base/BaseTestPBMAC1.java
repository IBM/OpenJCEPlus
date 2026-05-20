/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.OpenJCEPlusFIPS;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPBMAC1 extends BaseTestJunit5 {
    private List<String> algorithms = Arrays.asList("PBEWithHmacSHA1", "PBEWithHmacSHA224", "PBEWithHmacSHA256", "PBEWithHmacSHA384", 
            "PBEWithHmacSHA512", "PBEWithHmacSHA512/224", "PBEWithHmacSHA512/256");
    private List<String> fipsalgorithms = Arrays.asList("PBEWithHmacSHA384", "PBEWithHmacSHA512", "PBEWithHmacSHA512/224", "PBEWithHmacSHA512/256");

    private final String message = "This is a message for PBMAC1 testing";
    private final char[] PASSWORD = "passwordtryagain".toCharArray();
    private SecureRandom secureRandom = new SecureRandom();
    private byte[] salt = new byte[20];
    private int iterationCount = 300000;
    

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACFunctionality(String alg) throws Exception {
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && (alg.equalsIgnoreCase("PBEWithHmacSHA1") || 
            alg.equalsIgnoreCase("PBEWithHmacSHA224") || alg.equalsIgnoreCase("PBEWithHmacSHA256"))) {
            return;
        }
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = mac.doFinal(message.getBytes());
        assertNotEquals(null, macText, "Mac generated NULL");
        assertEquals(mac.getMacLength(), macText.length);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACReset(String alg) throws Exception {
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && (alg.equalsIgnoreCase("PBEWithHmacSHA1") || 
            alg.equalsIgnoreCase("PBEWithHmacSHA224") || alg.equalsIgnoreCase("PBEWithHmacSHA256"))) {
            return;
        }
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = mac.doFinal(message.getBytes());

        mac.reset();
        byte[] macText1 = mac.doFinal(message.getBytes());

        assertArrayEquals(macText, macText1);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACUpdate(String alg) throws Exception {
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && (alg.equalsIgnoreCase("PBEWithHmacSHA1") || 
            alg.equalsIgnoreCase("PBEWithHmacSHA224") || alg.equalsIgnoreCase("PBEWithHmacSHA256"))) {
            return;
        }
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = update(mac, message.getBytes(), 2);

        assertEquals(mac.getMacLength(), macText.length);
    }

    private byte[] update(Mac m, byte[] text, int updateLen) throws Exception {
        m.update(text, 0, updateLen);
        m.update(text, updateLen, updateLen);
        m.update(text, 2 * updateLen, text.length - (2 * updateLen));
        byte[] finalUpdate = m.doFinal();
        
        return finalUpdate;
    }

    @ParameterizedTest
    @FieldSource("fipsalgorithms")
    void testPBMAC1FIPSExceptions(String alg) throws Exception {
        if (!getProviderName().startsWith("OpenJCEPlusFIPS")) {
            return;
        }
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());

        try {
            byte[] smallSalt = new byte[8];
            secureRandom.nextBytes(smallSalt);
            mac.init(key, new PBEParameterSpec(smallSalt, iterationCount));
            fail("Expected InvalidKeyException not thrown, small salt length");
        } catch (InvalidKeyException e) {
            assertTrue(true);
        }

        try {
            mac.init(key, new PBEParameterSpec(salt, 100));
            fail("Expected InvalidKeyException not thrown, small iteration count");
        } catch (InvalidKeyException e) {
            assertTrue(true);
        }

        try {
            SecretKey smallPasswordKey = new SecretKeySpec("pa".toString().getBytes(), alg);
            mac.init(smallPasswordKey, new PBEParameterSpec(salt, iterationCount));
            fail("Expected InvalidKeyException not thrown, small password length");
        } catch (InvalidKeyException e) {
            assertTrue(true);
        }
    }

    @Test
    void testPBMAC1WithPKCS12() throws Exception {
        /*
         * The following test are adopted from RFC:
         * https://www.rfc-editor.org/rfc/rfc9579.html
         */
        if (getProviderName().equals("OpenJCEPlus")) {
            Security.insertProviderAt(new OpenJCEPlus(), 1);
        } else {
            Security.insertProviderAt(new OpenJCEPlusFIPS(), 1);
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");

        String base64 = new String(Files.readAllBytes(Paths.get("src/test/java/ibm/jceplus/junit/base/params/file1.txt")));
        String cleanedBase64 = base64.replaceAll("\\s+", "");
        byte[] decodedBytes = Base64.getDecoder().decode(cleanedBase64);
        try {
            ks.load(new ByteArrayInputStream(decodedBytes), "1234".toCharArray());
        } catch (Exception e) {
            fail(e.getMessage());
        }

        base64 = new String(Files.readAllBytes(Paths.get("src/test/java/ibm/jceplus/junit/base/params/file2.txt")));
        cleanedBase64 = base64.replaceAll("\\s+", "");
        decodedBytes = Base64.getDecoder().decode(cleanedBase64);
        try {
            ks.load(new ByteArrayInputStream(decodedBytes), "1234".toCharArray());
        } catch (java.io.IOException e) {
            fail(e.getMessage());
        }

        base64 = new String(Files.readAllBytes(Paths.get("src/test/java/ibm/jceplus/junit/base/params/file3.txt")));
        cleanedBase64 = base64.replaceAll("\\s+", "");
        decodedBytes = Base64.getDecoder().decode(cleanedBase64);
        try {
            ks.load(new ByteArrayInputStream(decodedBytes), "1234".toCharArray());
        } catch (java.io.IOException e) {
            fail(e.getMessage());
        }

        base64 = new String(Files.readAllBytes(Paths.get("src/test/java/ibm/jceplus/junit/base/params/file4.txt")));
        cleanedBase64 = base64.replaceAll("\\s+", "");
        decodedBytes = Base64.getDecoder().decode(cleanedBase64);
        try {
            ks.load(new ByteArrayInputStream(decodedBytes), "1234".toCharArray());
        } catch (java.io.IOException e) {
            // Expected error (Incorrect iteration count)
        }

        base64 = new String(Files.readAllBytes(Paths.get("src/test/java/ibm/jceplus/junit/base/params/file5.txt")));
        cleanedBase64 = base64.replaceAll("\\s+", "");
        decodedBytes = Base64.getDecoder().decode(cleanedBase64);
        try {
            ks.load(new ByteArrayInputStream(decodedBytes), "1234".toCharArray());
        } catch (java.io.IOException e) {
            // Expected error (Incorrect salt)
        }

        base64 = new String(Files.readAllBytes(Paths.get("src/test/java/ibm/jceplus/junit/base/params/file6.txt")));
        cleanedBase64 = base64.replaceAll("\\s+", "");
        decodedBytes = Base64.getDecoder().decode(cleanedBase64);
        try {
            ks.load(new ByteArrayInputStream(decodedBytes), "1234".toCharArray());
        } catch (java.io.IOException e) {
            // Expected error (Missing key length)
        }
    }
}
