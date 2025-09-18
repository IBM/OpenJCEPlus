/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BaseTestPBES2Parameters extends BaseTestJunit5 {

    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256"})
    public void testParameters(String algorithm) throws Exception {
        PBEKeySpec ks = new PBEKeySpec("password".toCharArray());
        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, getProviderName());
        SecretKey key = skf.generateSecret(ks);

        Cipher c = Cipher.getInstance(algorithm, getProviderName());
        c.init(Cipher.ENCRYPT_MODE, key);
        c.doFinal("This is just an example".getBytes());

        AlgorithmParameters params = c.getParameters();

        AlgorithmParameters testParams = AlgorithmParameters.getInstance(algorithm, getProviderName());
        testParams.init(params.getEncoded());

        assertEquals(algorithm, testParams.getAlgorithm());
        PBEParameterSpec spec = params.getParameterSpec(PBEParameterSpec.class);
        PBEParameterSpec testSpec = testParams.getParameterSpec(PBEParameterSpec.class);
        assertArrayEquals(spec.getSalt(), testSpec.getSalt());
        assertEquals(spec.getIterationCount(), testSpec.getIterationCount());
        assertArrayEquals(params.getEncoded(), testParams.getEncoded());
    }
}
