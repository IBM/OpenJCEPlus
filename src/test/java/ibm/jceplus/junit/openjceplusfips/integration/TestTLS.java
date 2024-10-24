/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplusfips.integration;

import ibm.jceplus.junit.base.integration.BaseTestTLS;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class TestTLS extends BaseTestTLS {

    private static boolean insertProviderUponCleanup = false;

    @BeforeAll
    public static void init() throws Exception {
        if (java.security.Security.getProvider("OpenJCEPlus") != null) {
            insertProviderUponCleanup = true;
            java.security.Security.removeProvider("OpenJCEPlus");
        }
        insertProvider("OpenJCEPlusFIPS", "com.ibm.crypto.plus.provider.OpenJCEPlusFIPS", 1);
    }

    @AfterAll
    public static void cleanup() throws Exception {
        if (insertProviderUponCleanup) {
            insertProvider("OpenJCEPlus", "com.ibm.crypto.plus.provider.OpenJCEPlus", 2);
        }
    }
    
    @ParameterizedTest
    @CsvSource({"TLSv1.3,rsa_pkcs1_sha1,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pkcs1_sha256,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pkcs1_sha384,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pkcs1_sha512,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,ec_rsa_pkcs1_sha256,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,ecdsa_sha256,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,ecdsa_secp384r1_sha384,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,ecdsa_secp521r1_sha512,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pss_rsae_sha256,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pss_rsae_sha384,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pss_rsae_sha512,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pss_pss_sha256,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pss_pss_sha384,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pss_pss_sha512,TLS_AES_128_GCM_SHA256",
        "TLSv1.3,rsa_pkcs1_sha1,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pkcs1_sha256,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pkcs1_sha384,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pkcs1_sha512,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,ec_rsa_pkcs1_sha256,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,ecdsa_sha256,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,ecdsa_secp384r1_sha384,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,ecdsa_secp521r1_sha512,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pss_rsae_sha256,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pss_rsae_sha384,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pss_rsae_sha512,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pss_pss_sha256,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pss_pss_sha384,TLS_AES_256_GCM_SHA384",
        "TLSv1.3,rsa_pss_pss_sha512,TLS_AES_256_GCM_SHA384",
        "TLSv1.2,ecdsa_sha256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLSv1.2,ec_rsa_pkcs1_sha256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLSv1.2,rsa_pss_pss_sha384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLSv1.2,rsa_pss_pss_sha512,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLSv1.2,rsa_pss_pss_sha384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLSv1.2,rsa_pss_pss_sha512,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLSv1.2,ecdsa_secp384r1_sha384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLSv1.2,rsa_pss_pss_sha384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLSv1.2,ec_rsa_pkcs1_sha256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLSv1.2,rsa_pss_pss_sha512,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLSv1.2,rsa_pss_pss_sha256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLSv1.2,rsa_pss_pss_sha512,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLSv1.2,rsa_pkcs1_sha1,TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLSv1.2,rsa_pss_rsae_sha512,TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLSv1.2,rsa_pkcs1_sha256,TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLSv1.2,rsa_pss_rsae_sha384,TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLSv1.2,rsa_pss_rsae_sha256,TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLSv1.2,rsa_pkcs1_sha384,TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "TLSv1.2,dsa_sha256,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"})
    public void testTLS(String tlsProtocol, String keyType, String cipher) throws Exception {
        runServerClient(tlsProtocol, keyType, cipher);
    }
}
