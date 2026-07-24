/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;
import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterNonFIPS;
import java.security.Provider;
import java.security.ProviderException;
import sun.security.util.Debug;

/**
 * NativeCryptoSelector manages the selection and initialization of cryptographic backends.
 * It uses the NativeProvider attribute from Provider services to determine which backend 
 * to use (OCK or OpenSSL), and delegates all cryptographic operations to the selected backend.
 * 
 * Rules:
 * - No value, blank, or missing NativeProvider attribute defaults to OCK
 * - "OCK" explicitly selects OCK backend (case-insensitive)
 * - "OpenSSL" selects OpenSSL backend (case-insensitive)
 * - Each backend is initialized only once, on first use via initialize() method
 */
public class NativeCryptoSelector {
    
    /**
     * Enum representing the available cryptographic backends
     */
    public enum Backend {
        OCK,
        OPENSSL
    }

    static final String DEBUG_VALUE = "jceplus";
    protected static final Debug debug = Debug.getInstance(DEBUG_VALUE); 

    // Backend implementation instances (will be set by concrete implementations)
    private static volatile NativeInterface ockBackend = null;
    private static volatile NativeInterface opensslBackend = null;
    private static volatile NativeInterface ockBackendFIPS = null;
    private static volatile NativeInterface opensslBackendFIPS = null;
    
    /**
     * Gets the backend implementation for the specified backend type.
     * 
     * @param backend the backend type
     * @return the backend implementation, or null if not set
     */
    private static NativeInterface getBackend(Backend backend, boolean isFIPS) {
        if (backend == Backend.OCK) {
            if (isFIPS) {
                if (ockBackendFIPS == null) {
                    ockBackendFIPS = NativeOCKAdapterFIPS.getInstance();
                } 
                return ockBackendFIPS;
            } else {
                if (ockBackend == null) {
                    ockBackend = NativeOCKAdapterNonFIPS.getInstance();
                } 
                return ockBackend;
            }
        } else if (backend == Backend.OPENSSL) {
            if (isFIPS) {
                throw new ProviderException("FIPS not supported through OpenSSL.");
            } else {
                return NativeOpenSSLAdapterNonFIPS.getInstance();
            }
        }
        return null;
    }
    
    /**
     * Determines which backend to use by querying the Provider service attribute.
     * Retrieves the NativeProvider attribute from provider.getService(type, algorithm).
     * 
     * @param provider the security provider
     * @param type the service type (e.g., "Cipher", "MessageDigest")
     * @param algorithm the algorithm name (e.g., "AES", "SHA-256")
     * @return the Backend to use
     */
    public static NativeInterface selectBackend(OpenJCEPlusProvider provider, String type, String algorithm) {
        Backend bked = Backend.OCK;
        Provider.Service service = null;

        if (provider != null && type != null && algorithm != null) {
            
            if (debug != null) {
                debug.println("Service - " + type + "\nAlg - " + algorithm);
            }

            service = provider.getService(type, algorithm);

            if (service != null) {
                String nativeProviderValue = service.getAttribute("NativeProvider");
                bked = selectBackendFromAttribute(nativeProviderValue);
            } else {
                // Service not found.
                throw new ConfigurationException("Service not found for type " + type + " and algorithm " + algorithm);
            }
        } else {
            throw new ConfigurationException("Provider, Type and Algorithm must not be null");
        }

        if (debug != null) {
            debug.println("Selected Backend: " + bked);
        }

        return getBackend(bked, provider.isFIPS());
    }
    
    /**
     * Determines which backend to use based on the NativeProvider attribute value.
     * 
     * @param nativeProviderValue the value of the NativeProvider attribute
     * @return the Backend to use
     */
    private static Backend selectBackendFromAttribute(String nativeProviderValue) {
        if (nativeProviderValue == null || nativeProviderValue.trim().isEmpty()) {
            // Default to OCK when no value or blank
            return Backend.OCK;
        }
        
        String normalized = nativeProviderValue.trim().toUpperCase();
        
        switch (normalized) {
            case "OPENSSL":
                return Backend.OPENSSL;
            case "OCK":
                return Backend.OCK;
            default:
                // If not OCK or OpenSSL throw an exception
                throw new ConfigurationException("Native backend unknown - " + nativeProviderValue);
        }

    }
}
