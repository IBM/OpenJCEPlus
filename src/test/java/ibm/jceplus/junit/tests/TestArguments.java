/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

/**
 * Utility class for generating test parameter variations.
 */
public class TestArguments {

    /**
     * Generates combinations of all aes key sizes and OpenJCEPlus* providers under test.
     * 
     * If no tags are found, all variations are returned.
     *
     * @return Stream of Arguments containing key sizes and OpenJCEPlus* providers
     */
    public static Stream<Arguments> aesKeySizesAndJCEPlusProviders() {
        int[] keySizes = {128, 192, 256};

        // Get active provider tags from -Dgroups system property
        String[] groupPropertyTags = BaseTest.getTagsPropertyAsArray();

        // Check if provider tags are present and build a list. Defaults to all providers.
        List<TestProvider> activeProviders = new ArrayList<>();
        if (groupPropertyTags.length == 0) {
            activeProviders.add(TestProvider.OpenJCEPlus);
            activeProviders.add(TestProvider.OpenJCEPlusFIPS);
        } else {
            for (String tag : groupPropertyTags) {
                if (TestProvider.OpenJCEPlus.getProviderName().equalsIgnoreCase(tag)) {
                    activeProviders.add(TestProvider.OpenJCEPlus);
                } else if (TestProvider.OpenJCEPlusFIPS.getProviderName().equalsIgnoreCase(tag)) {
                    activeProviders.add(TestProvider.OpenJCEPlusFIPS);
                }
            }
        }

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
}
