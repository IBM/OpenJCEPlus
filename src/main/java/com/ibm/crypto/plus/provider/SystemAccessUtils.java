/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Utility methods for system operations.
 *
 * <p>On JDK 25 and later the SecurityManager and {@code AccessController}
 * have been removed.  These methods are plain pass-through wrappers kept
 * so that callers require no changes.
 */
public final class SystemAccessUtils {

    private SystemAccessUtils() {}

    // -----------------------------------------------------------------------
    // System property access
    // -----------------------------------------------------------------------

    /**
     * Returns the value of the named system property, or {@code null} if it
     * is not set.
     *
     * @param key the property name
     * @return the property value, or {@code null}
     */
    public static String getSystemProperty(String key) {
        return System.getProperty(key);
    }

    /**
     * Returns the value of the named system property, or {@code defaultValue}
     * if it is not set.
     *
     * @param key          the property name
     * @param defaultValue the default value
     * @return the property value, or {@code defaultValue}
     */
    public static String getSystemProperty(String key, String defaultValue) {
        return System.getProperty(key, defaultValue);
    }

    // -----------------------------------------------------------------------
    // File system operations
    // -----------------------------------------------------------------------

    /**
     * Returns {@code true} if the file or directory at {@code path} exists.
     *
     * @param path the file system path to test
     * @return {@code true} if the path exists
     */
    public static boolean fileExists(String path) {
        return Files.exists(Paths.get(path));
    }

    /**
     * Opens a {@link FileReader} for the file at {@code path}.
     *
     * @param path the path to the file
     * @return a new {@link FileReader}
     * @throws IOException if the file cannot be opened
     */
    public static FileReader newFileReader(String path) throws IOException {
        return new FileReader(path);
    }

    /**
     * Loads the native library at the given library name.
     *
     * @param libraryName the path to the native library file
     */
    public static void loadLibrary(String libraryName) {
        System.load(libraryName);
    }

    /**
     * Returns the canonical path of a File object.
     *
     * @param file the File object
     * @return the canonical path
     * @throws IOException if an I/O error occurs
     */
    public static String getFileCanonicalPath(java.io.File file) throws IOException {
        return file.getCanonicalPath();
    }

    /**
     * Loads the class with the given class name using reflection.
     *
     * @param className the class name
     * @return the {@link Class} object
     * @throws ClassNotFoundException if the class cannot be found
     */
    public static Class<?> forName(String className) throws ClassNotFoundException {
        return Class.forName(className);
    }

    /**
     * No-op on JDK 25 and later: {@code SecurityManager} and
     * {@code AccessController} have been removed, so pre-loading
     * {@code sun.security.util} classes under {@code doPrivileged} is no
     * longer necessary.  The method is retained so that existing call sites
     * require no changes.
     */
    public static void preloadSunSecurityUtilClasses() {
        // no-op: SecurityManager removed in JDK 25
    }
}
