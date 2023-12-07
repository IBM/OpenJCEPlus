/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.lang.reflect.Modifier;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;

public class BaseTestImplementationClassesFinal extends BaseTest {
    //--------------------------------------------------------------------------
    //
    //
    public BaseTestImplementationClassesFinal(String providerName) {
        super(providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void testImplementationClassesFinal() throws Exception {
        Provider provider = Security.getProvider(providerName);
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

        assertTrue("Non-final implementation classes for " + nonFinalClassNames.toString(),
                (nonFinalClassNames.size() == 0));
    }
}
