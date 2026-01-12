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
import java.security.ProviderException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class OpenJCEPlusFIPS extends OpenJCEPlusProvider {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = 929669768004683845L;

    private static final boolean printFipsDeveloperModeWarning = Boolean.parseBoolean(System.getProperty("openjceplus.fips.devmodewarn", "true"));

    private static final boolean allowNonOAEPFIPS = Boolean.parseBoolean(System.getProperty("com.ibm.openjceplusfips.allowNonOAEP", "false"));

    private static final String info = "OpenJCEPlusFIPS Provider implements the following:\n" +

            "Algorithm parameter                : AES, DiffieHellman, DSA, EC, GCM, OAEP, RSAPSS\n"
            + "Algorithm parameter generator      : DiffieHellman, DSA, EC, GCM\n"
            + "Cipher algorithms                  : AES, RSA\n"
            + "Key agreement algorithms           : DiffieHellman, ECDH\n"
            + "Key factory                        : DiffieHellman,  DSA, EC, RSA, RSAPSS\n"
            + "Key generator                      : AES, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512 \n"
            + "                                                   HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512\n"
            + "kda-hkdf-with-sha224, " + "kda-hkdf-with-sha256,kda-hkdf-with-sha384, "
            + "kda-hkdf-with-sha512\n"
            + "Key pair generator                 : DiffieHellman, EC, RSA\n"
            + "Message authentication code (MAC)  :   HmacSHA224, HmacSHA256,\n"
            + "                                       HmacSHA384, HmacSHA512\n"
            + "                                                   HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512\n"
            + "Message digest                     : SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512\n"
            + "Secret key factory                 : AES, PBKDF2WithHmacSHA224, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512\n"
            + "Secure random                      : HASHDRBG, SHA256DRBG, SHA512DRBG\n"
            + "Signature algorithms               : NONEwithDSA, SHA224withDSA, SHA256withDSA,\n"
            + "                                     NONEwithECDSA, SHA224withECDSA,\n"
            + "                                       SHA256withECDSA, SHA384withECDSA, SHA512withECDSA,\n"
            + "                                       NONEwithRSA, SHA1withRSA, SHA224withRSA,\n"
            + "                                       SHA256withRSA, SHA384withRSA, SHA512withRSA, RSAPSS\n";

    private static final String OID_PKCS3 = "1.2.840.113549.1.3.1";

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile OpenJCEPlusFIPS instance;

    private static boolean ockInitialized = false;
    private static OCKContext ockContext;

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

    public OpenJCEPlusFIPS() {
        super("OpenJCEPlusFIPS", info);
        if (debug != null) {
            debug.println("New OpenJCEPlusFIPS instance");
        }

        if (!isFIPSCertifiedPlatform) {
            if (printFipsDeveloperModeWarning) {
                System.out.println("WARNING: OpenJCEPlusFIPS is running in developer mode. Non production workload assumed. This environment is not certified for FIPS 140-3: " + osName + ":" + osArch);
            }
            if (debug != null) {
                debug.println("WARNING: OpenJCEPlusFIPS is running in developer mode.  Non production workload assumed. This environment is not certified for FIPS 140-3: " + osName + ":" + osArch);
            }
        }

        // Print FIPS 140-3 mode message for s390x Linux or z/OS platforms
        if (osArch.contains("s390x")) {
            System.out.println("FIPS 140-3 mode enabled (for evaluation only, not supported for production use)");
            if (debug != null) {
                debug.println("FIPS 140-3 mode enabled (for evaluation only, not supported for production use)");
            }
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
            ProviderServiceReader config = new ProviderServiceReader(new BufferedReader(new StringReader(DefaultFIPSProviderAttrs.getConfigString())));  
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
            debug.println("OpenJCEPlusFIPS Build-Level: " + getDebugDate(this.getClass().getName()));
            debug.println("OpenJCEPlusFIPS library build date: " + OCKContext.getLibraryBuildDate());
            try {
                debug.println("OpenJCEPlusFIPS dependent library version: " + ockContext.getOCKVersion());
                debug.println("OpenJCEPlusFIPS dependent library path: " + ockContext.getOCKInstallPath());
            } catch (Throwable t) {
                t.printStackTrace(System.out);
            }
        }
    }

    // Return the instance of this class or create one if needed.
    //
    static OpenJCEPlusFIPS getInstance() {
        if (instance == null) {
            return new OpenJCEPlusFIPS();
        }
        return instance;
    }

    private static class OpenJCEPlusFIPSContext extends ProviderContext {

        private static final long serialVersionUID = 8282405867396835112L;

        OpenJCEPlusFIPSContext() {}

        OpenJCEPlusProvider getProvider() {
            return OpenJCEPlusFIPS.getInstance();
        }
    }

    ProviderContext getProviderContext() {
        return new OpenJCEPlusFIPSContext();
    }

    /**
     * Indicate whether the platform is certified FIPS or when FIPS is simulated on non-certified platforms.
     * @return true if FIPS is active (certified or simulated)
     */
    @Override
    boolean isFIPS() {
        return super.isFIPS() || !isFIPSCertifiedPlatform;
    }

    // Get SecureRandom to use for crypto operations. Returns a FIPS
    // approved SecureRandom to use. Ignore any user supplied
    // SecureRandom in FIPS mode.
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
        // to instantiate an OpenJCEPlusFIPS provider at the same time, we need
        // to ensure that the initialization only happens one time. We have
        // made the method synchronizaed to ensure only one thread can execute
        // the method at a time.
        //
        if (ockInitialized) {
            return;
        }

        try {
            boolean useFIPSMode = true;
            if (!isFIPSCertifiedPlatform) {
                if (printFipsDeveloperModeWarning) {
                    System.out.println("WARNING: OpenJCEPlusFIPS is about to load non FIPS 140-3 library!");
                }
                if (debug != null) {
                    debug.println("WARNING: OpenJCEPlusFIPS is about to load non FIPS 140-3 library!");
                }
                useFIPSMode = false;
            }

            ockContext = OCKContext.createContext(useFIPSMode);
            ockInitialized = true;
        } catch (OCKException e) {
            throw providerException("Failed to initialize OpenJCEPlusFIPS provider", e);
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlusFIPS provider", t);

            if (exceptionToThrow.getCause() == null) {
                // We are not including the full stack trace back to the point
                // of origin. Try and obtain the message for the underlying
                // cause of the exception.
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
        // deserialized in a JVM that has not instantiated the 
        // OpenJCEPlusFIPS provider yet.
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
