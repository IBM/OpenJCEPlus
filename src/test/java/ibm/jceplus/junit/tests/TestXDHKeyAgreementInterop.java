/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@Tag(Tags.OPENJCEPLUS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunECInteropProvider")
public class TestXDHKeyAgreementInterop extends BaseTestInterop {
    
    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    protected KeyPairGenerator kpg1;
    protected KeyPairGenerator kpg2;
    protected KeyAgreement ka1;
    protected KeyAgreement ka2;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);

        kpg1 = KeyPairGenerator.getInstance("XDH", getInteropProviderName());
        kpg2 = KeyPairGenerator.getInstance("XDH", getProviderName());
        ka1 = KeyAgreement.getInstance("XDH", getInteropProviderName());
        ka2 = KeyAgreement.getInstance("XDH", getProviderName());
    }

    @Test
    public void testKey() throws Exception {
        KeyPair kp1 = kpg1.generateKeyPair();
        KeyPair kp2 = kpg2.generateKeyPair();

        ka1.init(kp1.getPrivate());
        ka1.doPhase(kp2.getPublic(), true);
        
        ka2.init(kp2.getPrivate());
        ka2.doPhase(kp1.getPublic(), true);

        byte[] ss1 = ka1.generateSecret();
        byte[] ss2 = ka2.generateSecret();

        assertArrayEquals(ss1, ss2, "Key Agreement not compatible with different key providers");

        ka1.init(kp2.getPrivate());
        ka1.doPhase(kp1.getPublic(), true);

        ka2.init(kp1.getPrivate());
        ka2.doPhase(kp2.getPublic(), true);

        byte[] ss3 = ka1.generateSecret();
        byte[] ss4 = ka2.generateSecret();

        assertArrayEquals(ss3, ss4, "Key Agreement not compatible with different key providers");
    }
}
