/*
 * Copyright IBM Corp. 2025, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.ProviderServiceReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidParameterException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.OPENJCEPLUS_MULTITHREAD_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestProviderServices extends BaseTest {
    
    @Parameter(0)
    TestProvider provider;

    @Test
    public void testDefaultsServices() throws Exception {
        try {
            System.out.println("Testing services for provider: ");
            ProviderServiceReader reader = new ProviderServiceReader("./src/test/ProviderDefAttrs.config");
            reader.readServices();
            List<ProviderServiceReader.ServiceDefinition> services = reader.readServices();
            
            System.out.println("Found " + services.size() + " service definitions: for  " + reader.getName());
            System.out.println("Description: " + reader.getDesc());
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
                            System.out.println("               key - " + en.getKey());
                            System.out.println("               value - " + en.getValue());                             
                        }
                    }
                }
                System.out.println();
            } 
            
        } catch (Exception e) {
            System.err.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
        }

        assertTrue(true);
    } 
   
    @Test
    public void testDefServicesAddAlias() throws Exception {
        
        String config = "name = test\n"
            + "description =  OpenJCEPlus-test Provider\n"
            + "default = true\n"
            + "AlgorithmParameters.CCM.alias.add = TEST, JOHN";

        Provider provider1 = new OpenJCEPlus();
        BufferedReader br = new BufferedReader(new StringReader(config));
        Provider provider2 = ((OpenJCEPlus) provider1).configure(br);
             
        List<String> Alaises = getAliases(provider2, "AlgorithmParameters", "CCM");
        for (String alias : Alaises) {
            System.out.println(alias);
        }
        List<String> expected = Arrays.asList("AESCCM", "TEST", "JOHN");
        assertEquals(expected, Alaises);

        for (String alias : Alaises) {
            System.out.println(alias);
        }
    }

    @Test
    public void testDefServicesAddAliasNoAlias() throws Exception {
        
        String config = "name = test\n"
            + "description =  OpenJCEPlus-test Provider\n"
            + "default = true\n"
            + "AlgorithmParameters.CCM.alias.add =";

        Provider provider1 = new OpenJCEPlus();
        BufferedReader br = new BufferedReader(new StringReader(config));
        Provider provider2 = ((OpenJCEPlus) provider1).configure(br);
             
        List<String> Alaises = getAliases(provider2, "AlgorithmParameters", "CCM");
        List<String> expected = Arrays.asList("AESCCM");
        assertEquals(expected, Alaises);

        for (String alias : Alaises) {
            System.out.println(alias);
        }
    }

    @Test
    public void testDefServicesDelAlias() throws Exception {
        
        String config = "name = test\n"
            + "description =  OpenJCEPlus-test Provider\n"
            + "default = true\n"
            + "AlgorithmParameters.CCM.alias.add = TEST, JOHN\n"
            + "AlgorithmParameters.CCM.alias.delete = TEST";

        Provider provider1 = new OpenJCEPlus();
        BufferedReader br = new BufferedReader(new StringReader(config));
        Provider provider2 = ((OpenJCEPlus) provider1).configure(br);
             
        List<String> Alaises = getAliases(provider2, "AlgorithmParameters", "CCM");
        List<String> expected = Arrays.asList("AESCCM", "JOHN");
        assertEquals(expected, Alaises);

        for (String alias : Alaises) {
            System.out.println(alias);
        }
    }

    @Test
    public void testDefServicesReplaceAlias() throws Exception {
        
        String config = "name = test\n"
            + "description =  OpenJCEPlus-test Provider\n"
            + "default = true\n"
            + "AlgorithmParameters.CCM.alias.replace = TEST, JOHN";

        Provider provider1 = new OpenJCEPlus();
        BufferedReader br = new BufferedReader(new StringReader(config));
        Provider provider2 = ((OpenJCEPlus) provider1).configure(br);
             
        List<String> Alaises = getAliases(provider2, "AlgorithmParameters", "CCM");
        List<String> expected = Arrays.asList("TEST", "JOHN");
        assertEquals(expected, Alaises);

        for (String alias : Alaises) {
            System.out.println(alias);
        }
    }

    @Test
    public void testDefServicesAddAttribute() throws Exception {
        
        String config = "name = test\n"
            + "description =  OpenJCEPlus-test Provider\n"
            + "default = true\n"
            + "AlgorithmParameters.CCM.attr.add.TestAttr1 = TestValue1\n"
            + "AlgorithmParameters.CCM.attr.add.TestAttr2 = TestValue2";

        Provider provider1 = new OpenJCEPlus();
        BufferedReader br = new BufferedReader(new StringReader(config));
        Provider provider2 = ((OpenJCEPlus) provider1).configure(br);
             
        // Get the service
        Provider.Service service = provider2.getService("AlgorithmParameters", "CCM");
        
        // Verify the added attributes exist
        String attr1 = service.getAttribute("TestAttr1");
        String attr2 = service.getAttribute("TestAttr2");
        
        assertEquals("TestValue1", attr1, "TestAttr1 should have value TestValue1");
        assertEquals("TestValue2", attr2, "TestAttr2 should have value TestValue2");

        System.out.println("TestAttr1: " + attr1);
        System.out.println("TestAttr2: " + attr2);
    }

    @Test
    public void testDefServicesDelAttribute() throws Exception {
        
        String config = "name = test\n"
            + "description =  OpenJCEPlus-test Provider\n"
            + "default = true\n"
            + "AlgorithmParameters.CCM.attr.add.TestAttr1 = TestValue1\n"
            + "AlgorithmParameters.CCM.attr.add.TestAttr2 = TestValue2\n"
            + "AlgorithmParameters.CCM.attr.delete.TestAttr1 = ";

        Provider provider1 = new OpenJCEPlus();
        BufferedReader br = new BufferedReader(new StringReader(config));
        Provider provider2 = ((OpenJCEPlus) provider1).configure(br);
             
        // Get the service
        Provider.Service service = provider2.getService("AlgorithmParameters", "CCM");
        
        // Verify TestAttr1 was deleted and TestAttr2 still exists
        String attr1 = service.getAttribute("TestAttr1");
        String attr2 = service.getAttribute("TestAttr2");
        
        assertEquals(null, attr1, "TestAttr1 should be deleted (null)");
        assertEquals("TestValue2", attr2, "TestAttr2 should still have value TestValue2");

        System.out.println("TestAttr1 (should be null): " + attr1);
        System.out.println("TestAttr2: " + attr2);
    }

    @Test
    public void testCompareProviders() throws Exception {
        String configNonFIPS = "./src/test/ProviderDefAttrs.config";
        String configFIPS = "./src/test/ProviderFIPSDefAttrs.config";
        String config = null;
        Provider provider1 = null;
        Provider provider2 = null;

        setAndInsertProvider(provider);

        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            if (provider.getName().equals(getProviderName())) {
                provider1 = provider;
            }
        }

        if (getProviderName().equalsIgnoreCase("OpenJCEPlus")) {
            config = configNonFIPS;
            provider2 = provider1.configure(config);
        } else if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            config = configFIPS;
            provider2 = (new OpenJCEPlus()).configure(config);
        }

        Set<Provider.Service> services1 = provider1.getServices();
        Set<Provider.Service> services2 = provider2.getServices();

        //Check the number of entries in each provider they need to match
        assertEquals(services1.size(), services2.size(), "Providers have different number of entries");
          
        assertTrue(compareServices(services1, provider1, provider2), "Providers have different services");
    }

    @Test
    public void testProviderServicesNameErrorTest() throws Exception {
        String config = null;
        BufferedReader rd = null;
        boolean result = false;
        
        try {
            //No Name in config
            config = "description =  OpenJCEPlus-test Provider\n"
                + "default = true\n"
                + "AlgorithmParameters.CCM.attr.add.TestAttr1 = TestValue1\n"
                + "AlgorithmParameters.CCM.attr.add.TestAttr2 = TestValue2\n"
                + "AlgorithmParameters.CCM.attr.delete.TestAttr1 = ";
            rd = new BufferedReader(new StringReader(config));
            Provider provider1 = new OpenJCEPlus();
            ((OpenJCEPlus) provider1).configure(rd);

        } catch (InvalidParameterException ipe) {
            System.out.println(ipe.getMessage());
            result = true;
        }

        if (!result) {
            fail("No Name was excepted");
        }   
    }

    @Test
    public void testProviderServicesFIleErrorTest() throws Exception { 
        boolean result = false;

        try {
            //File not found
            ProviderServiceReader reader = new ProviderServiceReader("./src/test/ProviderDefAttrs.confg");
            reader.readServices();
        } catch (IOException ioe) {
            System.out.println(ioe.getMessage());
            result = true;
        }

        if (!result) {
            fail("File was expected to not be found");
        }    
    }

    @Test
    public void testProviderServicesFileNullErrorTest() throws Exception {
        String config = null;
        boolean result = false;
        
        try {
            //File null
            ProviderServiceReader reader = new ProviderServiceReader(config);
            reader.readServices();
        } catch (IOException ioe) {
            System.out.println(ioe.getMessage());
            result = true;
        }

        if (!result) {
            fail("File was expected to be null");
        }
    }

    @Test
    public void testProviderServicesBufferReaderNullErrorTest() throws Exception {
        BufferedReader rd = null;
        boolean result = false;

        try {
            //bufferedreader null
            ProviderServiceReader reader = new ProviderServiceReader(rd);
            reader.readServices();
        } catch (IOException ioe) {
            System.out.println(ioe.getMessage());
            result = true;
        }

        if (!result) {
            fail("BufferedReader was expected to be null");
        }
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
            if (key.startsWith("Alg.Alias." + type + ".")) {               
                String aliasAlgorithm = provider.getProperty(key);
                if (algorithm.equals(aliasAlgorithm)) {
                    // Extract the alias name from the key
                    String aliasName = key.substring(("Alg.Alias." + type + ".").length());
                    aliases.add(aliasName);
                }
            }
        }
        return aliases;
    }
}
