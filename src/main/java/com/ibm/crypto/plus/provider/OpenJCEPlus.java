/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.OCKContext;
import com.ibm.crypto.plus.provider.base.OCKException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.List;

public final class OpenJCEPlus extends OpenJCEPlusProvider {

    private static final long serialVersionUID = -1610967128950682479L;

    private static final String info = "OpenJCEPlus Provider implements the following:\n"
            + "Algorithm parameter                : AES, ChaCha20, ChaCha20-Poly1305, DESede, DiffieHellman, DSA, EC, XEC, GCM, CCM, OAEP, RSAPSS\n"
            + "                                       PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256\n"
            + "                                       PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256\n"
            + "                                       PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256, PBEWithHmacSHA512/224AndAES_128, PBEWithHmacSHA512/224AndAES_256\n"
            + "                                       PBEWithHmacSHA512/256AndAES_128, PBEWithHmacSHA512/256AndAES_256\n"
            + "                                       PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithSHA1AndRC2_128, PBEWithSHA1AndRC4_40, PBEWithSHA1AndRC4_128\n"                                    
            + "Algorithm parameter generator      :  DiffieHellman, DSA, EC, XEC, GCM, CCM\n"
            + "Cipher algorithms                  : AES, ChaCha20, ChaCha20-Poly1305, DESede, RSA\n"
            + "                                       PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256\n"
            + "                                       PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256\n"
            + "                                       PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256, PBEWithHmacSHA512/224AndAES_128, PBEWithHmacSHA512/224AndAES_256\n"
            + "                                       PBEWithHmacSHA512/256AndAES_128, PBEWithHmacSHA512/256AndAES_256\n"  
            + "                                       PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithSHA1AndRC2_128, PBEWithSHA1AndRC4_40, PBEWithSHA1AndRC4_128\n"        
            + "Key agreement algorithms           : DiffieHellman, ECDH, XDH\n"
            + "Key Encapsulation Mechanisms       : ML-KEM-512, ML-KEM-768, ML-KEM-1024\n"
            + "Key factory                        : DiffieHellman, DSA, EC, XEC,  RSA, RSAPSS, ML-KEM-512, ML-KEM-768, ML-KEM-1024\n"
            + "Key generator                      : AES, ChaCha20, DESede, HmacMD5, HmacSHA1, HmacSHA224,\n"
            + "                                       HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512,\n"
            + "                                       HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512,\n"
            + "                                       kda-hkdf-witH-sha1, kda-hkdf-with-sha224,\n"
            + "                                       kda-hkdf-with-sha256, kda-hkdf-with-sha384,\n"
            + "                                       kda-hkdf-with-sha512\n"
            + "Key pair generator                 : DiffieHellman, DSA, EC, XEC, RSA, ML-DSA-44, ML-DSA-65, ML-DSA-87,\n"
            + "                                       ML-KEM-512, ML-KEM-768, ML-KEM-1024\n"
            + "Message authentication code (MAC)  : HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512\n"
            + "                                       , HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512\n"
            + "Message digest                     : MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512\n"
            + "Secret key factory                 : AES, ChaCha20, DESede, PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA224, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512\n"
            + "                                       PBKDF2WithHmacSHA512/224, PBKDF2WithHmacSHA512/256\n"
            + "                                       PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256, PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256\n"
            + "                                       PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256, PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256\n"
            + "                                       PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256, PBEWithHmacSHA512/224AndAES_128, PBEWithHmacSHA512/224AndAES_256\n"
            + "                                       PBEWithHmacSHA512/256AndAES_128, PBEWithHmacSHA512/256AndAES_256\n"
            + "                                       PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithSHA1AndRC2_128, PBEWithSHA1AndRC4_40, PBEWithSHA1AndRC4_128\n"               
            + "Secure random                      : HASHDRBG, SHA256DRBG, SHA512DRBG\n"
            + "Signature algorithms               : NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA,\n"
            + "                                       SHA3-224withDSA, SHA3-256withDSA, SHA3-384withDSA, SHA3-512withDSA,\n"
            + "                                       NONEwithECDSA, SHA1withECDSA, SHA224withECDSA,\n"
            + "                                       SHA256withECDSA, SHA384withECDSA, SHA512withECDSA,\n"
            + "                                       SHA3-224withECDSA, SHA3-256withECDSA, SHA3-384withECDSA, SHA3-512withECDSA,\n"
            + "                                       NONEwithRSA, SHA1withRSA, SHA224withRSA,\n"
            + "                                       SHA256withRSA, SHA384withRSA, SHA512withRSA, RSAPSS, Ed25519, Ed448,\n"
            + "                                       SHA3-224withRSA, SHA3-256withRSA, SHA3-384withRSA, SHA3-512withRSA,\n"
            + "                                       ML_DSA_44, ML_DSA_65, ML_DSA_87\n";


    private static final String OID_PKCS3 = "1.2.840.113549.1.3.1";

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile OpenJCEPlus instance;

    private static boolean ockInitialized = false;
    private static OCKContext ockContext;

    public OpenJCEPlus() {
        super("OpenJCEPlus", info);

        if (debug != null) {
            debug.println("New OpenJCEPlus instance");
        }

        final OpenJCEPlusProvider jce = this;

        // Do java OCK initialization which includes loading native code
        // Don't do this in the static initializer because it might
        // be necessary for an applet running in a browser to grant
        // access rights beforehand.
        if (!ockInitialized) {
            initializeContext();
        }
 
        try {
            ProviderServiceReader config = new ProviderServiceReader(new BufferedReader(new StringReader(DefaultProviderAttrs.getConfigString())));  
            List<ProviderServiceReader.ServiceDefinition> services = config.readServices();
            for (ProviderServiceReader.ServiceDefinition service : services) {
                putService(new OpenJCEPlusService(jce, service.getType(), service.getAlgorithm(),
                    service.getClassName(), service.getAliases().toArray(new String[service.getAliases().size()]), service.getAttributes()));
            }
        } catch (IOException e) {
            throw new InvalidParameterException("Error configuring OpenJCEPlus provider - " + e.getMessage()); 
        }    
        
        if (instance == null) {
            instance = this;
        }

        if (debug != null) {
            debug.println("OpenJCEPlus Build-Level: " + getDebugDate(this.getClass().getName()));
            debug.println("OpenJCEPlus library build date: " + OCKContext.getLibraryBuildDate());
            try {
                debug.println("OpenJCEPlus dependent library version: " + ockContext.getOCKVersion());
                debug.println("OpenJCEPlus dependent library path: " + ockContext.getOCKInstallPath());
            } catch (Throwable t) {
                t.printStackTrace(System.out);
            }
        }
    }

    @Override
    public Provider configure(String configFile) throws InvalidParameterException {
        return new OpenJCEPlus(new ProviderServiceReader(configFile));
    }

    public Provider configure(BufferedReader br) throws InvalidParameterException {
        return new OpenJCEPlus(new ProviderServiceReader(br));
    }

    public OpenJCEPlus(ProviderServiceReader config) {
        super("OpenJCEPlus-" + config.getName(), config.getDesc());

        if (debug != null) {
            debug.println("New OpenJCEPlus instance");
        }

        final OpenJCEPlusProvider jce = this;

        // Do java OCK initialization which includes loading native code
        // Don't do this in the static initializer because it might
        // be necessary for an applet running in a browser to grant
        // access rights beforehand.
        if (!ockInitialized) {
            initializeContext();
        }
        
        try {
            List<ProviderServiceReader.ServiceDefinition> services = config.readServices();
            for (ProviderServiceReader.ServiceDefinition service : services) {
                putService(new OpenJCEPlusService(jce, service.getType(), service.getAlgorithm(),
                    service.getClassName(), service.getAliases().toArray(new String[service.getAliases().size()]), service.getAttributes()));
            }
        } catch (IOException e) {
            throw new InvalidParameterException("Error configuring OpenJCEPlus provider - " + e.getMessage()); 
        }         

        if (instance == null) {
            instance = this;
        }
    }

    // Return the instance of this class or create one if needed.
    //
    static OpenJCEPlus getInstance() {
        if (instance == null) {
            return new OpenJCEPlus();
        }
        return instance;
    }

    private static class OpenJCEPlusContext extends ProviderContext {

        private static final long serialVersionUID = -1409417302968036811L;

        OpenJCEPlusContext() {}

        OpenJCEPlusProvider getProvider() {
            return OpenJCEPlus.getInstance();
        }
    }

    ProviderContext getProviderContext() {
        return new OpenJCEPlusContext();
    }

    // Get SecureRandom to use for crypto operations.
    //
    java.security.SecureRandom getSecureRandom(java.security.SecureRandom userSecureRandom) {
        try {
            return java.security.SecureRandom.getInstance("SHA256DRBG", this);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException("SecureRandom not available");
        }
    }

    // Initialize OCK context(s)
    //
    private synchronized void initializeContext() {
        // Leave this duplicate check in here. If two threads are both trying
        // to instantiate an OpenJCEPlus provider at the same time, we need to
        // ensure that the initialization only happens one time. We have
        // made the method synchronizaed to ensure only one thread can execute
        // the method at a time.
        //
        if (ockInitialized) {
            return;
        }

        try {
            boolean useFIPSMode = false;

            ockContext = OCKContext.createContext(useFIPSMode);
            ockInitialized = true;
        } catch (OCKException e) {
            throw providerException("Failed to initialize OpenJCEPlus provider", e);
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlus provider", t);

            if (exceptionToThrow.getCause() == null) {
                // We are not including the full stack trace back to the point
                // of origin.
                // Try and obtain the message for the underlying cause of the
                // exception
                //
                // If an ExceptionInInitializerError or NoClassDefFoundError is
                // thrown, we want to get the message from the cause of that
                // exception.
                //
                if ((t instanceof java.lang.ExceptionInInitializerError)
                        || (t instanceof java.lang.NoClassDefFoundError)) {
                    Throwable cause = t.getCause();
                    if (cause != null) {
                        t = cause;
                    }
                }

                // In the case that the JNI library could not be loaded.
                //
                String message = t.getMessage();
                if ((message != null) && (message.length() > 0)) {
                    // We want to see the message for the underlying cause even
                    // if not showing the stack trace all the way back to the
                    // point of origin.
                    //
                    exceptionToThrow.initCause(new ProviderException(t.getMessage()));
                }
            }

            if (debug != null) {
                exceptionToThrow.printStackTrace(System.out);
            }

            throw exceptionToThrow;
        }
    }

    // Get OCK context for crypto operations
    //
    OCKContext getOCKContext() {
        // May need to initialize OCK here in the case that a serialized
        // OpenJCEPlus object, such as a HASHDRBG SecureRandom, is being
        // deserialized in a JVM that has not instantiated the OpenJCEPlus
        // provider yet.
        //
        if (!ockInitialized) {
            initializeContext();
        }

        return ockContext;
    }

    ProviderException providerException(String message, Throwable ockException) {
        ProviderException providerException = new ProviderException(message, ockException);
        setOCKExceptionCause(providerException, ockException);
        return providerException;
    }

    // Get the date from the ImplementationVersion in the manifest file
    private static String getDebugDate(String className) {
        String versionDate = "Unknown";
        try {
            Class<?> thisClass = Class.forName(className);
            Package thisPackage = thisClass.getPackage();
            String versionInfo = thisPackage.getImplementationVersion();
            int index = versionInfo.indexOf("_");
            versionDate = (index == -1) ? versionInfo : versionInfo.substring(index + 1);
        } catch (Exception e) {
            // IGNORE EXCEPTION
        }
        return versionDate;
    }
}
