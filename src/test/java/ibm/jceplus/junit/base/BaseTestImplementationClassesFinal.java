/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.lang.reflect.Modifier;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestImplementationClassesFinal extends BaseTestJunit5 {

    @Test
    public void testImplementationClassesFinal() throws Exception {
        Provider provider = Security.getProvider(getProviderName());
        Set<?> services = provider.getServices();
        Iterator<?> iterator = services.iterator();
        TreeSet<String> serviceClassNames = new TreeSet<String>();
        Vector<String> nonFinalClassNames = new Vector<String>();

        // Walk through all of the provider services and generate a unique list
        // of implementation class names.
        //
        while (iterator.hasNext()) {
            Provider.Service service = (Provider.Service) iterator.next();
            serviceClassNames.add(service.getClassName());
        }

        iterator = serviceClassNames.iterator();

        while (iterator.hasNext()) {
            String className = (String) iterator.next();

            try {
                Class<?> c = Class.forName(className);
                if (!Modifier.isFinal(c.getModifiers())) {
                    nonFinalClassNames.add(className);
                }
            } catch (Exception e) {
            }
        }

        assertTrue((nonFinalClassNames.size() == 0), "Non-final implementation classes for " + nonFinalClassNames.toString());
    }
}
