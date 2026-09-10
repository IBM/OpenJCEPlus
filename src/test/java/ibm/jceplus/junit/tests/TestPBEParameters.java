/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.AlgorithmParameters;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import sun.security.util.DerValue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@Tag(Tags.OPENJCEPLUS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestPBEParameters extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40", 
        "PBEWithSHA1AndRC2_128", "PBEWithSHA1AndRC4_40", "PBEWithSHA1AndRC4_128"})
    public void testParameters(String algorithm) throws Exception {
        PBEKeySpec ks = new PBEKeySpec("password".toCharArray());
        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, getProviderName());
        SecretKey key = skf.generateSecret(ks);

        Cipher c = Cipher.getInstance(algorithm, getProviderName());
        c.init(Cipher.ENCRYPT_MODE, key);

        AlgorithmParameters params = c.getParameters();
        byte[] encoded = params.getEncoded();

        // HmacSHA1 is the default PRF and MUST NOT be explicitly encoded in PBES2 parameters.
        // Navigate into PBKDF2-params and check the optional prf SEQUENCE is absent.
        if (algorithm.startsWith("PBEWithHmacSHA1And")) {
            DerValue pbes2 = new DerValue(encoded);               // PBES2-params SEQUENCE
            DerValue kdf = pbes2.data.getDerValue();              // keyDerivationFunc SEQUENCE
            kdf.data.getOID();                                    // skip id-PBKDF2 OID
            DerValue pbkdf2params = kdf.data.getDerValue();       // PBKDF2-params SEQUENCE
            pbkdf2params.data.getOctetString();                   // skip salt
            pbkdf2params.data.getInteger();                       // skip iterationCount
            pbkdf2params.data.getOptional(DerValue.tag_Integer);  // skip optional keyLength
            assertFalse(pbkdf2params.data.getOptional(DerValue.tag_Sequence).isPresent(),
                    algorithm + ": encoded PBES2 params must not contain HmacSHA1 prf.");
        }

        AlgorithmParameters testParams = AlgorithmParameters.getInstance(algorithm, getProviderName());
        testParams.init(encoded);

        assertEquals(algorithm, testParams.getAlgorithm());
        PBEParameterSpec spec = params.getParameterSpec(PBEParameterSpec.class);
        PBEParameterSpec testSpec = testParams.getParameterSpec(PBEParameterSpec.class);
        assertArrayEquals(spec.getSalt(), testSpec.getSalt());
        assertEquals(spec.getIterationCount(), testSpec.getIterationCount());
        assertArrayEquals(encoded, testParams.getEncoded());
    }
}
