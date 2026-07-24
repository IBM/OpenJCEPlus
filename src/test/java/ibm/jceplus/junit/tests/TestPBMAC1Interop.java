/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@Tag(Tags.OPENJCEPLUS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusOnly")
public class TestPBMAC1Interop extends BaseTestInterop {

    @Parameter(0)
    TestProvider provider;

    TestProvider interopProvider = TestProvider.SunJCE;

    private List<String> algorithms = Arrays.asList("PBEWithHmacSHA1", "PBEWithHmacSHA224", "PBEWithHmacSHA256", "PBEWithHmacSHA384", 
            "PBEWithHmacSHA512", "PBEWithHmacSHA512/224", "PBEWithHmacSHA512/256");

    private final String message = "This is a message for PBMAC1 testing";
    private final char[] PASSWORD = "passwordtryagain".toCharArray();
    private SecureRandom secureRandom = new SecureRandom();
    private byte[] salt = new byte[20];
    private int iterationCount = 300000;
    

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
        setInteropProviderName(interopProvider.name());
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACFunctionality(String alg) throws Exception {
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);

        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        Mac macInterop = Mac.getInstance(alg, getInteropProviderName());
        macInterop.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = mac.doFinal(message.getBytes());
        byte[] macInteropText = macInterop.doFinal(message.getBytes());

        assertArrayEquals(macInteropText, macText);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACUpdate(String alg) throws Exception {
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);

        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        Mac macInterop = Mac.getInstance(alg, getInteropProviderName());
        macInterop.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = update(mac, message.getBytes(), 2);
        byte[] macInteropText = update(macInterop, message.getBytes(), 2);

        assertArrayEquals(macText, macInteropText);
    }

    private byte[] update(Mac m, byte[] text, int updateLen) throws Exception {
        m.update(text, 0, updateLen);
        m.update(text, updateLen, updateLen);
        m.update(text, 2 * updateLen, text.length - (2 * updateLen));
        byte[] finalUpdate = m.doFinal();
        
        return finalUpdate;
    }
}
