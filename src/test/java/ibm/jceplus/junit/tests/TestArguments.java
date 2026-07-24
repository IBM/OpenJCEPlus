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
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

/**
 * Utility class for generating test parameter variations.
 */
public class TestArguments {

    /**
     * Generates combinations of OpenJCEPlus* providers with the SUN provider for interoperability testing.
     *
     * @return Stream of Arguments containing (JCEProviders, SUN) pairs
     */
    protected static Stream<Arguments> getOpenJCEPlusWithSUNInteropProvider(Set<String> providers) {
        return getOpenJCEPlusWithInteropProviders(providers, TestProvider.SUN);
    }

    /**
     * Generates combinations of OpenJCEPlus* providers with the SunJCE provider for interoperability testing.
     *
     * @return Stream of Arguments containing (JCEProviders, SunJCE) pairs
     */
    protected static Stream<Arguments> getOpenJCEPlusWithSunJCEInteropProvider(Set<String> providers) {
        return getOpenJCEPlusWithInteropProviders(providers, TestProvider.SunJCE);
    }

    /**
     * Generates combination of only OpenJCEPlus (non-FIPS) provider
     * with the BC provider for interoperability testing.
     *
     * @return Stream of Arguments containing (OpenJCEPlus, BC) pair
     */
    protected static Stream<Arguments> getOpenJCEPlusWithBCInteropProvider(Set<String> providers) {
        return getOpenJCEPlusWithInteropProviders(providers, TestProvider.BC);
    }

    public static Stream<Arguments> keySizesAndProviders(Set<String> providers, List<Integer> keySizes) {
        // Determine enabled providers.
        List<TestProvider> enabledProviders = getEnabledProviders(providers).toList();

        // Generate all combinations of key sizes and providers determined above.
        List<Arguments> arguments = new ArrayList<>();
        for (TestProvider provider : enabledProviders) {
            for (int keySize : keySizes) {
                arguments.add(Arguments.of(keySize, provider));
            }
        }

        if (arguments.isEmpty()) {
            throw new IllegalArgumentException("No test arguments, unlikely this is what was asked for.");
        }
        return arguments.stream();
    }

    /**
     * Resolves enabled OpenJCEPlus* providers from -Dgroups, defaulting to all specified through tags, if none are specified.
     *
     * @return A stream of enabled TestProvider.
     */
    protected static Stream<TestProvider> getEnabledProviders(Set<String> providers) {

        // Get active provider tags from -Dgroups system property
        String[] groupPropertyTags = BaseTest.getTagsPropertyAsArray();

        //retrieve enabled providers based on tags
        List<TestProvider> enabledProviders;
        List<TestProvider> taggedProviders = providers.stream().map(pName -> TestProvider.valueOf(pName)).collect(Collectors.toList());
        if (groupPropertyTags.length == 0) {
            enabledProviders = taggedProviders;
        } else {
            enabledProviders = new ArrayList<>();
            for (String tag : groupPropertyTags) {
                try {
                    TestProvider tp = TestProvider.valueOf(tag);
                    if (taggedProviders.contains(tp)) {
                        enabledProviders.add(tp);
                    }
                } catch (IllegalArgumentException | NullPointerException e) {
                    throw new IllegalStateException("The -Dgroup property values are incorrect", e);
                }
            }
        }
        return enabledProviders.stream();
    }

    /**
     * Generates combinations of OpenJCEPlus* providers with a specified interoperability provider for testing.
     *
     * @param interopProvider The interoperability provider to combine with OpenJCEPlus* providers
     * @return Stream of Arguments containing (JCEProviders, interopProvider) pairs
     */
    protected static Stream<Arguments> getOpenJCEPlusWithInteropProviders(Set<String> providers, TestProvider interopProvider) {
        List<TestProvider> enabledProviders = getEnabledProviders(providers).toList();

        List<Arguments> arguments = new ArrayList<>();
        for (TestProvider jceProvider : enabledProviders) {
            arguments.add(Arguments.of(jceProvider, interopProvider));
        }

        return arguments.stream();
    }
}
