/*
 * Copyright IBM Corp. 2025, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestAttributes extends BaseTestJunit5 {
    
    @Test
    public void testServices() throws Exception {
        Provider p = Security.getProvider(getProviderName());
        for (Provider.Service s : p.getServices()) {
            if (s.getType().equals("SecureRandom")) {
                testSecureRandom(SecureRandom.getInstance(s.getAlgorithm(), p));
            }
        }
    }

    private static void testSecureRandom(SecureRandom sr) {
        // Check for ThreadSafe Attribute
        String attr = sr.getProvider().getProperty("SecureRandom."
                + sr.getAlgorithm() + " ThreadSafe");
        
        assertTrue("true".equals(attr), "Not ThreadSafe" + attr);
    }
}
