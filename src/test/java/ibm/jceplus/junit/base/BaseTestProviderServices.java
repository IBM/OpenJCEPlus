/*
 * Copyright IBM Corp. 2025, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.ProviderServiceReader;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestProviderServices extends BaseTestJunit5 {
    
    @Test
    public void testServices() throws Exception {
        try {
            System.out.println("Testing services for provider: ");
            ProviderServiceReader reader = new ProviderServiceReader("./src/test/ProviderAttrs.config");
            List<ProviderServiceReader.ServiceDefinition> services = reader.readServices();
            
            System.out.println("Found " + services.size() + " service definitions: for  "+reader.getName());
            System.out.println("Description: "+reader.getDesc());
            System.out.println();
            
            // Group by type
            List<String> types = reader.getUniqueTypes(services);
            for (String type : types) {
                List<ProviderServiceReader.ServiceDefinition> typeServices = reader.filterByType(services, type);
                System.out.println(type + " (" + typeServices.size() + " services):");
                for (ProviderServiceReader.ServiceDefinition service : typeServices) {
                    System.out.println("  - " + service.getAlgorithm() + 
                                     " -> " + service.getClassName());
                    if (!service.getAliases().isEmpty()) {
                        System.out.println("    Aliases: " + service.getAliases());
                    } else {
                        System.out.println("    Aliases: Empty");
                    }                    
                    if (!service.getAttributes().isEmpty()) {
                        Map<String, String> attributes = service.getAttributes();
                        System.out.println("    Attributes: ");
                        for (Map.Entry<String, String> en : attributes.entrySet()) {
                            System.out.println("               key - "+en.getKey());
                            System.out.println("               value - "+en.getValue());                             
                        }
                    }
                }
                System.out.println();
            }
            
        } catch (Exception e) {
            System.err.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    @Test
    public void testCompareProviders() throws Exception {
        String config = "C:/Users/JohnPeck/work/OpenJCEPlus-work/ProviderAttrs.config";
        Provider provider1 = new OpenJCEPlus();
        Provider provider2 = provider1.configure(config);
        Security.addProvider(provider2);

        Set<Provider.Service> services1 = provider1.getServices();
        Set<Provider.Service> services2 = provider2.getServices();

        //Check the number of entries in each provider they need to match
        assertEquals(services1.size(), services2.size(), "Providers have different number of entries");
          
        assertTrue(compareServices(services1, provider1, provider2), "Providers have different services");
    }


    /**
     * Compares two service definitions and identifies differences.
     */
    private boolean compareServices(Set<Provider.Service> s1, Provider pr1, Provider pr2) {
        boolean result = true;

        for (Provider.Service service1 : s1) {
            
            Provider.Service service2 = pr2.getService(service1.getType(), service1.getAlgorithm());

            if (service2 == null) {
                result = false;
                break;
            }

            if (service1.getClassName().equals(service2.getClassName()) == false) {
                result = false; 
                break;
            }

            //compare aliases
            List<String> sortedList1 = new ArrayList<>(getAliases(pr1, service1.getType(), service1.getAlgorithm()));
            List<String> sortedList2 = new ArrayList<>(getAliases(pr2, service2.getType(), service2.getAlgorithm()));

            Collections.sort(sortedList1);
            Collections.sort(sortedList2);
            if (sortedList1.equals(sortedList2) == false) {
                result = false; 
                break;
            }
             
            //There is no way to compare Attributes. Since you can not get a list from the Provider object.
            return result;
        }   
        
        return result;
    }
    
    private List<String> getAliases(Provider provider, String type, String algorithm) {
        List<String> aliases = new ArrayList<>();
        // Iterate through all provider properties
        for (String key : provider.stringPropertyNames()) {
            // Check for alias properties specific to the type and algorithm
            if (key.startsWith("Alg. Alias." + type + ".")) {
                String aliasAlgorithm = provider.getProperty(key);
                if (algorithm.equals(aliasAlgorithm)) {
                    // Extract the alias name from the key
                    String aliasName = key.substring(("Alg. Alias." + type + ".").length());
                    aliases.add(aliasName);
                }
            }
        }
        return aliases;
    }
}
