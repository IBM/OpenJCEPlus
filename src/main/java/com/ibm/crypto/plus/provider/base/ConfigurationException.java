/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

/**
 * This is a class used for exceptions created by the native code that
 * utilizes the equivalent native libraries.
 *
 * The class can be subclassed by library-specific exception classes, or
 * be used directly by other classes who need to indicate that the problem
 * occured in native code, but might not have knowledge of the exact library
 * used.
 */
public class ConfigurationException extends java.lang.RuntimeException {

    private static final long serialVersionUID = 922337203685477578L;

    public ConfigurationException(String s) {
        super(s);
    }

    public ConfigurationException(String s, Throwable cause) {
        super(s, cause);
    }
}
