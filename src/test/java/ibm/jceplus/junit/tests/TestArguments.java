/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

/**
 * Utility class for generating test parameter variations.
 */
public class TestArguments {

    /**
     * Generates test combinations for each AES key size with the active OpenJCEPlus* providers.
     * 
     * @return Stream of Arguments containing AES key sizes and OpenJCEPlus* providers
     */ 
    public static Stream<Arguments> aesKeySizesAndJCEPlusProviders() {
        int[] aesKeySizes = {128, 192, 256};
        return keySizesAndJCEPlusProviders(aesKeySizes);
    }

    /**
     * Generates combinations of all key sizes and OpenJCEPlus* providers under test.
     * 
     * If no tags are found, all variations are returned.
     * 
     * @param keySizes Array of key sizes to combine with providers
     * 
     * @return Stream of Arguments containing key sizes and OpenJCEPlus* providers
     */
    private static Stream<Arguments> keySizesAndJCEPlusProviders(int[] keySizes) {

        // Check if provider tags are present and build a list. Defaults to all providers.
        List<TestProvider> activeProviders = getEnabledProviders().collect(Collectors.toList());

        // Generate all combinations of key sizes and providers determined above.
        List<Arguments> arguments = new ArrayList<>();
        for (TestProvider provider : activeProviders) {
            for (int keySize : keySizes) {
                arguments.add(Arguments.of(keySize, provider));
            }
        }

        if (arguments.isEmpty()) {
            throw new IllegalArgumentException("No test arguments, unlikey this is what was asked for.");
        }
        return arguments.stream();
    }

    /**
     * Resolves enabled OpenJCEPlus* providers from -Dgroups, defaulting to all when none are specified.
     *
     * @return A stream of enabled TestProvider.
     */ 
    protected static Stream<TestProvider> getEnabledProviders(){

        // Get active provider tags from -Dgroups system property
        String[] groupPropertyTags = BaseTest.getTagsPropertyAsArray();

        //retrieve enabled providers based on tags
        List<TestProvider> enabledProviders = new ArrayList<>();
        if (groupPropertyTags.length == 0) {
            enabledProviders.add(TestProvider.OpenJCEPlus);
            enabledProviders.add(TestProvider.OpenJCEPlusFIPS);
        } else {
            for (String tag : groupPropertyTags) {
                if (TestProvider.OpenJCEPlus.getProviderName().equalsIgnoreCase(tag)) {
                    enabledProviders.add(TestProvider.OpenJCEPlus);
                } else if (TestProvider.OpenJCEPlusFIPS.getProviderName().equalsIgnoreCase(tag)) {
                    enabledProviders.add(TestProvider.OpenJCEPlusFIPS);
                }
            }
        }
        return enabledProviders.stream();
    }     
}
