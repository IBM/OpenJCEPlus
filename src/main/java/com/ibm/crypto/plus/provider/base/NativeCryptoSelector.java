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
import java.security.Provider;
import java.util.Objects;
import sun.security.util.Debug;

/**
 * BackendCryptoSelector manages the selection and initialization of cryptographic backends.
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
    
    // Locks for thread-safe initialization
    private static final Object ockLock = new Object();
    private static final Object opensslLock = new Object();
    
    /**
     * Sets the OCK backend implementation.
     * This should be called during system initialization.
     * 
     * @param backend the OCK backend implementation
     */
    public static void setOCKBackend(NativeInterface backend) {
        ockBackend = backend;
    }
    
    /**
     * Sets the OpenSSL backend implementation.
     * This should be called during system initialization.
     * 
     * @param backend the OpenSSL backend implementation
     */
    public static void setOpenSSLBackend(NativeInterface backend) {
        opensslBackend = backend;
    }
    
    /**
     * Gets the backend implementation for the specified backend type.
     * 
     * @param backend the backend type
     * @return the backend implementation, or null if not set
     */
    public static NativeInterface getBackend(Backend backend, boolean isFIPS) {
        if (backend == Backend.OCK) {
            if (isFIPS) {
                ockBackendFIPS = Objects.requireNonNullElseGet(ockBackendFIPS, () -> NativeOCKAdapterFIPS.getInstance());
                return ockBackendFIPS;
            } else {
                ockBackend = Objects.requireNonNullElseGet(ockBackend, () -> NativeOCKAdapterNonFIPS.getInstance());
                return ockBackend;
            }
        } else if (backend == Backend.OPENSSL) {
            return opensslBackend;
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
                // Service not found, default to OCK
                String nativeProviderValue = service.getAttribute("NativeProvider");
                bked = selectBackendFromAttribute(nativeProviderValue);
            }
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
        
        if ("OPENSSL".equals(normalized)) {
            return Backend.OPENSSL;
        } else {
            // Default to OCK for any other value including "OCK"
            return Backend.OCK;
        }

    }
}
