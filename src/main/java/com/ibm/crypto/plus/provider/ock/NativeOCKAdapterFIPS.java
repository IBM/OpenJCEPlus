/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import sun.security.util.Debug;

public class NativeOCKAdapterFIPS extends NativeOCKAdapter {
    private static final boolean printFipsDeveloperModeWarning = Boolean.parseBoolean(System.getProperty("openjceplus.fips.devmodewarn", "true"));

    // User enabled debugging
    private static final String DEBUG_VALUE = "jceplus";
    private static Debug debug = Debug.getInstance(DEBUG_VALUE);

    private static final boolean isFIPSCertifiedPlatform;
    private static final Map<String, List<String>> supportedPlatforms = new HashMap<>();
    private static final String osName;
    private static final String osArch;

    static {
        supportedPlatforms.put("Arch", List.of("amd64", "ppc64", "s390x"));
        supportedPlatforms.put("OS", List.of("Linux", "AIX", "Windows"));

        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");;

        boolean isOsSupported, isArchSupported;
        // Check whether the OpenJCEPlus FIPS is supported.
        isOsSupported = false;
        for (String os: supportedPlatforms.get("OS")) {
            if (osName.contains(os)) {
                isOsSupported = true;
                break;
            }
        }
        isArchSupported = false;
        for (String arch: supportedPlatforms.get("Arch")) {
            if (osArch.contains(arch)) {
                isArchSupported = true;
                break;
            }
        }
        isFIPSCertifiedPlatform = isOsSupported && isArchSupported;
    }

    private static volatile NativeOCKAdapterFIPS instance = null;

    private NativeOCKAdapterFIPS(boolean useFIPSMode) {
        super(useFIPSMode);
    }

    public static NativeOCKAdapterFIPS getInstance() {
        if (instance == null) {
            boolean useFIPSMode = checkFIPSMode();
            instance = new NativeOCKAdapterFIPS(useFIPSMode);
        }

        return instance;
    }

    private static boolean checkFIPSMode() {
        if (!isFIPSCertifiedPlatform) {
            if (printFipsDeveloperModeWarning) {
                System.out.println("WARNING: OpenJCEPlusFIPS is about to load non FIPS 140-3 library!");
            }
            if (debug != null) {
                debug.println("WARNING: OpenJCEPlusFIPS is about to load non FIPS 140-3 library!");
            }
            return false;
        }
        return true;
    }
}
