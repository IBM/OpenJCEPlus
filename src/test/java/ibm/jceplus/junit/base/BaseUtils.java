/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.Provider;

abstract public class BaseUtils {

    public static final String PROVIDER_BC = "BC"; // BouncyCastle
    public static final String PROVIDER_SUN = "SUN"; // SUN
    public static final String PROVIDER_SunJCE = "SunJCE"; // SunJCE
    public static final String PROVIDER_SunRsaSign = "SunRsaSign"; // SunRsaSign
    public static String PROVIDER_SunEC = "SunEC"; // SunEC
    public static final String PROVIDER_OpenJCEPlus = "OpenJCEPlus";
    public static final String PROVIDER_OpenJCEPlusFIPS = "OpenJCEPlusFIPS";


    // --------------------------------------------------------------------------------------
    //
    //
    public static String bytesToHex(byte[] input) {
        if (input == null) {
            return "<NULL>";
        }

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < input.length; ++i) {
            sb.append(String.format("%02x", input[i] & 0xff));
        }

        return sb.toString();
    }


    // --------------------------------------------------------------------------------------
    //
    //
    public static byte[] generateBytes(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i % 256);
        }
        return bytes;
    }


    public static byte[] hexStringToByteArray(String string) {
        String s = string.trim().replaceAll(" +", ""); // remove all spaces

        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }


    public static Provider loadProvider(String providerName, String providerClassName)
            throws Exception {
        return loadProvider(providerName, providerClassName, true);
    }


    public static Provider loadProvider(String providerName, String providerClassName,
            boolean addToProviderList) throws Exception {
        Provider provider = java.security.Security.getProvider(providerName);
        if (provider == null) {
            provider = (Provider) Class.forName(providerClassName).getDeclaredConstructor().newInstance();
            if (addToProviderList) {
                java.security.Security.addProvider(provider);
            }
        }

        return provider;
    }


    public static Provider loadProviderBC() throws Exception {
        return loadProvider(PROVIDER_BC, "org.bouncycastle.jce.provider.BouncyCastleProvider");
    }


    public static Provider loadProviderOpenJCEPlus() throws Exception {
        return loadProvider(PROVIDER_OpenJCEPlus, "com.ibm.crypto.plus.provider.OpenJCEPlus");
    }


    public static Provider loadProviderOpenJCEPlusFIPS() throws Exception {
        return loadProvider(PROVIDER_OpenJCEPlusFIPS,
                "com.ibm.crypto.plus.provider.OpenJCEPlusFIPS");
    }
}

