/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestAESGCMWithKeyAndIvCheck extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    private static final byte[] AAD = new byte[5];
    private static final byte[] PT = new byte[18];
    protected int specifiedKeySize = 16;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    /*
     * Used when the same key+iv was already used for one encryption,
     * and the next encryption is attempted with the same key+iv.
     *
     * OpenJCEPlus checks for key+iv reuse when encryption starts, in
     * update() or doFinal(). updateAAD() only buffers the AAD and has no
     * check of its own, so it is not the first call that fails.
     * update() fails first and sets the "re-init required" flag. After that,
     * updateAAD() and doFinal() also throw ISE.
     */
    private void checkISE(Cipher c) throws Exception {
        try {
            c.update(PT);
            throw new Exception("Should throw ISE for update()");
        } catch (IllegalStateException ise) {
            // expected
        }
        try {
            c.updateAAD(AAD);
            throw new Exception("Should throw ISE for updateAAD() after failed reuse");
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
    public void testParameterlessInitUsesNewIvEachTime() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        SecretKey key = new SecretKeySpec(new byte[specifiedKeySize], "AES");
        c.init(Cipher.ENCRYPT_MODE, key);

        byte[] previousIv = null;
        for (int i = 0; i < 3; i++) {
            c.updateAAD(AAD);
            byte[] ct = c.doFinal(PT); // must not throw ISE
            byte[] iv = c.getIV();

            if (previousIv != null && Arrays.equals(previousIv, iv)) {
                throw new Exception("IV was reused in iteration " + i);
            }
            previousIv = iv;

            // The ciphertext must decrypt with the IV that was used for it.
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            dec.init(Cipher.DECRYPT_MODE, key, c.getParameters());
            dec.updateAAD(AAD);
            byte[] recovered = dec.doFinal(ct);
            if (!Arrays.equals(recovered, PT)) {
                throw new Exception("decryption result mismatch in iteration " + i);
            }
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

        /**
         * Parameter-less init: the provider generates the next IV itself, so a
         * subsequent encryption is allowed (see
         * testParameterlessInitUsesNewIvEachTime).
         */

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

