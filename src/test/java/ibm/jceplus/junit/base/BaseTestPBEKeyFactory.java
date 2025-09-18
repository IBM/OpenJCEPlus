/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPBEKeyFactory extends BaseTestJunit5 {

    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256"})
    public void testValid(String algorithm) throws Exception {

        SecretKeyFactory fac = SecretKeyFactory.getInstance(algorithm, getProviderName());

        char[] pass = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        PBEKeySpec spec = new PBEKeySpec(pass);
        SecretKey skey = fac.generateSecret(spec);
        KeySpec spec1 = fac.getKeySpec(skey, PBEKeySpec.class);
        SecretKey skey1 = fac.generateSecret(spec1);
        assertEquals(skey, skey1);
    }

    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256"})
    public void testInvalid(String algorithm) throws Exception {

        SecretKeyFactory fac = SecretKeyFactory.getInstance(algorithm, getProviderName());

        char[] pass = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', '\u0019'};
        PBEKeySpec spec = new PBEKeySpec(pass);
        try {
            SecretKey skey = fac.generateSecret(spec);
            fail("Expected InvalidKeySpecException for algorithm: " + skey.getAlgorithm() + " but none was thrown.");
        } catch (InvalidKeySpecException e) {
            assertEquals("Invalid Password.", e.getMessage());
        }
    }
}
