/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.io.File;
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

    /**
     * Generates combinations of OpenJCEPlus* providers with the SunEC provider for interoperability testing.
     *
     * @return Stream of Arguments containing (JCEProviders, SunEC) pairs
     */
    protected static Stream<Arguments> getOpenJCEPlusWithSunECInteropProvider(Set<String> providers) {
        return getOpenJCEPlusWithInteropProviders(providers, TestProvider.SunEC);
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

        // z/OS does not build an OpenSSL native library, so OpenSSL-backed provider
        // tests must never run there regardless of how the suite was invoked.
        if (System.getProperty("os.name", "").contains("z/OS")) {
            enabledProviders.removeIf(tp -> tp == TestProvider.OpenJCEPlus_OpenSSL);
        }

        // OpenSSL-backed tests require the OpenSSL native library (libopenjceplus_64)
        // to be physically present on disk.  We check for the file using the same
        // path-resolution logic as NativeOpenSSLImplementation.preloadOpenJCEPlusNative()
        // so that the guard fires precisely when the library cannot be loaded, regardless
        // of which system properties happen to be set by the caller.
        if (!isOpenSSLNativeLibraryPresent()) {
            enabledProviders.removeIf(tp -> tp == TestProvider.OpenJCEPlus_OpenSSL);
        }

        return enabledProviders.stream();
    }

    /**
     * Returns true if the OpenJCEPlus OpenSSL native library file exists on disk at the
     * path that NativeOpenSSLImplementation would attempt to load it from.
     * Mirrors the path-resolution logic in NativeOpenSSLImplementation.preloadOpenJCEPlusNative().
     */
    static boolean isOpenSSLNativeLibraryPresent() {
        String osName = System.getProperty("os.name", "");
        String osArch = System.getProperty("os.arch", "");

        // Determine the directory to search
        String libDir;
        String ojpOverridePath = System.getProperty("openjceplus.library.path");
        if (ojpOverridePath != null) {
            libDir = ojpOverridePath;
        } else {
            String javaHome = System.getProperty("java.home", "");
            libDir = javaHome + File.separator + (osName.startsWith("Windows") ? "bin" : "lib");
        }

        // Determine the expected filename (mirrors NativeOpenSSLImplementation)
        String libName;
        if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            libName = "libopenjceplus_64.dll";
        } else if (osName.equals("Mac OS X")) {
            libName = "libopenjceplus.dylib";
        } else {
            libName = "libopenjceplus_64.so";
        }

        return new File(libDir, libName).exists();
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
