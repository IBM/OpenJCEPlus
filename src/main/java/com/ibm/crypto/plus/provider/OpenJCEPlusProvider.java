/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKContext;
import java.lang.ref.Cleaner;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.KDFParameters;
import javax.crypto.SecretKey;
import sun.security.util.Debug;

// Internal interface for OpenJCEPlus and OpenJCEPlus implementation classes.
// Implemented as an abstract class rather than an interface so that 
// methods can be package protected, as interfaces have only public methods.
// Code is not implemented in this class to ensure that any thread call
// stacks show it originating in the specific provider class.
//
public abstract class OpenJCEPlusProvider extends java.security.Provider {
    private static final long serialVersionUID = 1L;

    private static final String PROVIDER_VER = System.getProperty("java.specification.version");

    private static final String JAVA_VER = System.getProperty("java.specification.version");

    static final String DEBUG_VALUE = "jceplus";

    static final boolean allowLegacyHKDF = Boolean.getBoolean("openjceplus.allowLegacyHKDF");

    private final transient Cleaner[] cleaners;

    private final int DEFAULT_NUM_CLEANERS = 2;

    private final int numCleaners;

    private AtomicInteger count = new AtomicInteger(0);

    @SuppressWarnings("exports")
    protected static final Debug debug = Debug.getInstance(DEBUG_VALUE); 

    OpenJCEPlusProvider(String name, String info) {
        super(name, PROVIDER_VER, info);

        numCleaners = Integer.getInteger("openjceplus.cleaners.num", DEFAULT_NUM_CLEANERS);
        if (numCleaners < 1){
            throw new IllegalArgumentException(numCleaners + " is an invalid number of cleaner threads, must be at least 1.");
        }

        cleaners = new Cleaner[numCleaners];
        for (int i = 0; i < numCleaners; i++) {
            final Cleaner cleaner = Cleaner.create();
            cleaners[i] = cleaner;
        }
    }

    /**
     * Any primitive instance variable whose value is changed after calling registerCleanable()
     * in the constructor must be changed to the PrimitiveWrapper type if the variable is passed
     * as a parameter to the Runnable cleaning method. This is to ensure the variable is passed by
     * reference instead of by value.
     */
    public void registerCleanable(Object owner, Runnable cleanAction) {
        Cleaner cleaner = cleaners[Math.abs(count.getAndIncrement() % numCleaners)];
        cleaner.register(owner, cleanAction);
    }

    @SuppressWarnings("exports")
    public static Debug getDebug() {
        return debug;
    }
    
    // Get OCK context for crypto operations
    //
    abstract OCKContext getOCKContext();

    // Get the context associated with the provider. The context is used in
    // serialization to be able to keep track of the associated provider.
    //
    abstract ProviderContext getProviderContext();

    // Get SecureRandom to use for crypto operations. If in FIPS mode, returns a
    // FIPS
    // approved SecureRandom to use.
    //
    abstract java.security.SecureRandom getSecureRandom(
            java.security.SecureRandom userSecureRandom);

    // Return whether the provider is FIPS. If the provider is using an OCK
    // context in FIPS mode then it is FIPS.
    //
    boolean isFIPS() {
        return getOCKContext().isFIPS();
    }

    // Return the Java version.
    //
    String getJavaVersionStr() {
        return JAVA_VER;
    }

    abstract ProviderException providerException(String message, Throwable ockException);

    void setOCKExceptionCause(Exception exception, Throwable ockException) {
        if ((debug != null) && (exception != null) && (exception.getCause() == null)) {
            exception.initCause(ockException);
        }
    }

    protected static class OpenJCEPlusService extends Service {
        private static Class<?> openjceplusClass;

        OpenJCEPlusService(Provider provider, String type, String algorithm, String className,
                String[] aliases) {
            this(provider, type, algorithm, className, aliases, null);
        }

        OpenJCEPlusService(Provider provider, String type, String algorithm, String className,
                String[] aliases, Map<String, String> attributes) {
            super(provider, type, algorithm, className, toList(aliases), attributes);

            if (debug != null) {
                debug.println("Constructing OpenJCEPlusService: " + provider + ", " + type
                            + ", " + algorithm + ", " + className);
            }
        }

        private static List<String> toList(String[] aliases) {
            return (aliases == null) ? null : Arrays.asList(aliases);
        }

        private Class<?> getParameterClass(String type) {
            if ("KDF".equalsIgnoreCase(type)) {
                return KDFParameters.class;
            }
            
            return null;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            Provider provider = getProvider();
            String className = getClassName();
            String type = getType();
            String algorithm = getAlgorithm();

            // AlgorithmParameters instances don't need the provider as a parameter,
            // so the superclass constructor can be used.
            if ("AlgorithmParameters".equalsIgnoreCase(type)) {
                return super.newInstance(constructorParameter);
            }

            Class<?> cls;
            try {
                cls = Class.forName(className);
            } catch (ClassNotFoundException e) {
                throw new NoSuchAlgorithmException("class configured for " + type + " (provider: "
                        + provider.getName() + ") cannot be found.", e);
            }

            // Call the constructor that takes an OpenJCEPlusProvider if
            // available
            //
            try {
                Class<?>[] parameters;
                Class<?> ctrParamClz = null;
                if (constructorParameter != null) {
                    ctrParamClz = getParameterClass(type);
                }
                if (ctrParamClz != null) {
                    parameters = new Class<?>[2];
                    
                    Class<?> argClass = constructorParameter.getClass();
                    if (!ctrParamClz.isAssignableFrom(argClass)) {
                        throw new InvalidParameterException("constructorParameter must be "
                            + "instanceof " + ctrParamClz.getName().replace('$', '.')
                            + " for type " + type);
                    }

                    parameters[1] = ctrParamClz;
                } else {
                    parameters = new Class<?>[1];
                }
                if (openjceplusClass == null) {
                    openjceplusClass = Class
                            .forName("com.ibm.crypto.plus.provider.OpenJCEPlusProvider");
                }
                parameters[0] = openjceplusClass;
                Constructor<?> constr = cls.getConstructor(parameters);

                Object[] ctrParams;
                if ((constructorParameter != null) && (ctrParamClz != null)) {
                    ctrParams = new Object[2];
                    ctrParams[1] = constructorParameter;
                } else {
                    ctrParams = new Object[1];
                }
                ctrParams[0] = provider;

                return constr.newInstance(ctrParams);
            } catch (InvocationTargetException e) {
                throw new NoSuchAlgorithmException("Error constructing implementation (algorithm: "
                    + algorithm + ", provider: " + provider.getName()
                    + ", class: " + className + ")", e.getCause());
            } catch (Exception e) {
                throw new NoSuchAlgorithmException("Error constructing implementation (algorithm: "
                    + algorithm + ", provider: " + provider.getName()
                    + ", class: " + className + ")", e);
            }
        }

        @Override
        public boolean supportsParameter(Object parameter) {

            if (parameter == null) {
                return false;
            }
            if (parameter instanceof Key == false) {
                throw new InvalidParameterException("Parameter must be a Key");
            }
            Key key = (Key) parameter;

            if (key instanceof SecretKey) {

                String keyType = ((SecretKey) key).getFormat();
                if (keyType == null) {
                    // this happens when encoding is not supported
                    return true;
                }
                if (keyType.equalsIgnoreCase("RAW") || keyType.equalsIgnoreCase("PKCS5_DERIVED_KEY")
                        || keyType.equalsIgnoreCase("PKCS5_KEY")) {
                    return true;
                } else {
                    return false;
                }

            } else if (key instanceof PrivateKey) {
                String keyType = ((PrivateKey) key).getFormat();
                if (keyType == null) {
                    // this happens when encoding is not supported
                    return true;
                }
                if (keyType.equalsIgnoreCase("PKCS#8")) {
                    return true;
                } else {
                    return false;
                }
            } else if (key instanceof PublicKey) {
                String keyType = ((PublicKey) key).getFormat();
                if (keyType == null) {
                    // this happens when encoding is not supported
                    return true;
                }
                if (keyType.equalsIgnoreCase("X.509")) {
                    return true;
                } else {
                    return false;
                }
            }

            return false;
        }

        @Override
        public String toString() {

            return (super.toString() + "\n" + "provider = " + this.getProvider().getName() + "\n"
                    + "algorithm = " + this.getAlgorithm());

        }

    }
}
