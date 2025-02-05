/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestAESGCMWithKeyAndIvCheck extends BaseTestJunit5 {

    private static final byte[] AAD = new byte[5];
    private static final byte[] PT = new byte[18];
    protected int specifiedKeySize = 16;

    private void checkISE(Cipher c) throws Exception {
        // Subsequent encryptions should fail
        try {
            c.updateAAD(AAD);
            throw new Exception("Should throw ISE for updateAAD()");
        } catch (IllegalStateException ise) {
            // expected
        }

        try {
            c.update(PT);
            throw new Exception("Should throw ISE for update()");
        } catch (IllegalStateException ise) {
            // expected
        }
        try {
            c.doFinal(PT);
            throw new Exception("Should throw ISE for doFinal()");
        } catch (IllegalStateException ise) {
            // expected
        }
    }

    @Test
    public void testKeyAndIv() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        SecretKey key = new SecretKeySpec(new byte[specifiedKeySize], "AES");
        // First try parameter-less init.
        c.init(Cipher.ENCRYPT_MODE, key);
        c.updateAAD(AAD);
        byte[] ctPlusTag = c.doFinal(PT);

        // subsequent encryption should fail unless re-init w/ different key+iv
        checkISE(c);

        // Validate the retrieved parameters against the IV and tag length.
        AlgorithmParameters params = c.getParameters();
        if (params == null) {
            throw new Exception("getParameters() should not return null");
        }
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        if (spec.getTLen() != (ctPlusTag.length - PT.length) * 8) {
            throw new Exception("Parameters contains incorrect TLen value");
        }
        if (!Arrays.equals(spec.getIV(), c.getIV())) {
            throw new Exception("Parameters contains incorrect IV value");
        }

        // Should be ok to use the same key+iv for decryption
        c.init(Cipher.DECRYPT_MODE, key, params);
        c.updateAAD(AAD);
        byte[] recovered = c.doFinal(ctPlusTag);
        if (!Arrays.equals(recovered, PT)) {
            throw new Exception("decryption result mismatch");
        }

        // Now try to encrypt again using the same key+iv; should fail also
        try {
            c.init(Cipher.ENCRYPT_MODE, key, params);
            throw new Exception("Should throw exception when same key+iv is used");
        } catch (InvalidAlgorithmParameterException iape) {
            // expected
        }

        // Now try to encrypt again using parameter-less init; should work
        c.init(Cipher.ENCRYPT_MODE, key);
        c.doFinal(PT);

        // make sure a different iv is used
        byte[] iv = c.getIV();
        if (Arrays.equals(spec.getIV(), iv)) {
            throw new Exception("IV should be different now");
        }

        // Now try to encrypt again using a different parameter; should work
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[30]));
        c.updateAAD(AAD);
        c.doFinal(PT);
        // subsequent encryption should fail unless re-init w/ different key+iv
        checkISE(c);

        // Now try decryption twice in a row; no re-init required and
        // same parameters is used.
        c.init(Cipher.DECRYPT_MODE, key, params);
        c.updateAAD(AAD);
        recovered = c.doFinal(ctPlusTag);

        c.updateAAD(AAD);
        recovered = c.doFinal(ctPlusTag);
        if (!Arrays.equals(recovered, PT)) {
            throw new Exception("decryption result mismatch");
        }

        // Now try decryption again and re-init using the same parameters
        c.init(Cipher.DECRYPT_MODE, key, params);
        c.updateAAD(AAD);
        recovered = c.doFinal(ctPlusTag);

        // init to decrypt w/o parameters; should fail with IKE as
        // javadoc specified
        try {
            c.init(Cipher.DECRYPT_MODE, key);
            throw new Exception("Should throw IKE for dec w/o params");
        } catch (InvalidKeyException ike) {
            // expected
        }

        // Lastly, try encryption AND decryption w/ wrong type of parameters,
        // e.g. IvParameterSpec
        try {
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            throw new Exception("Should throw IAPE");
        } catch (InvalidAlgorithmParameterException iape) {
            // expected
        }
        try {
            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            throw new Exception("Should throw IAPE");
        } catch (InvalidAlgorithmParameterException iape) {
            // expected
        }

        assertTrue(true, "Test Passed!");
    }


}

