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
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * Utility methods for running privileged operations on Java versions that
 * still have a SecurityManager (i.e. Java &lt; 25).
 *
 * <p>Each method wraps a specific system operation in
 * {@code AccessController.doPrivileged} so that it succeeds even when the
 * calling thread does not hold the required permission.
 *
 * <p>On JDK 25 and later where SecurityManager is removed, these methods
 * become pass-through operations.
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
    @SuppressWarnings("removal")
    public static String getSystemProperty(String key) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key));
    }

    /**
     * Returns the value of the named system property, or {@code defaultValue}
     * if it is not set.
     *
     * @param key          the property name
     * @param defaultValue the default value
     * @return the property value, or {@code defaultValue}
     */
    @SuppressWarnings("removal")
    public static String getSystemProperty(String key, String defaultValue) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key, defaultValue));
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
    @SuppressWarnings("removal")
    public static boolean fileExists(String path) {
        return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Files.exists(Paths.get(path)));
    }

    /**
     * Opens a {@link FileReader} for the file at {@code path} under
     * {@code doPrivileged}.
     *
     * @param path the path to the file
     * @return a new {@link FileReader}
     * @throws IOException if the file cannot be opened
     */
    @SuppressWarnings("removal")
    public static FileReader newFileReader(String path) throws IOException {
        try {
            return AccessController.doPrivileged(
                    (PrivilegedExceptionAction<FileReader>) () -> new FileReader(path));
        } catch (PrivilegedActionException pae) {
            Exception ex = pae.getException();
            if (ex instanceof IOException) {
                throw (IOException) ex;
            }
            throw new IOException(ex);
        }
    }

    /**
     * Loads the native library at the given library name under {@code doPrivileged}.
     *
     * @param libraryName the path to the native library file
     */
    @SuppressWarnings("removal")
    public static void loadLibrary(String libraryName) {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            System.load(libraryName);
            return null;
        });
    }

    /**
     * Returns the canonical path of a File object by calling getCanonicalPath()
     * under {@code doPrivileged}. Only getCanonicalPath() requires the permission check.
     *
     * @param file the File object
     * @return the canonical path
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("removal")
    public static String getFileCanonicalPath(java.io.File file) throws IOException {
        try {
            return AccessController.doPrivileged(
                    (PrivilegedExceptionAction<String>) () -> file.getCanonicalPath());
        } catch (PrivilegedActionException pae) {
            Exception ex = pae.getException();
            if (ex instanceof IOException) {
                throw (IOException) ex;
            }
            throw new IOException(ex);
        }
    }

    /**
     * Loads the class with the given class name using reflection
     * under {@code doPrivileged}.
     *
     * @param className the class name
     * @return the {@link Class} object
     * @throws ClassNotFoundException if the class cannot be found
     */
    @SuppressWarnings("removal")
    public static Class<?> forName(String className) throws ClassNotFoundException {
        try {
            return AccessController.doPrivileged(
                    (PrivilegedExceptionAction<Class<?>>) () -> Class.forName(className));
        } catch (PrivilegedActionException pae) {
            Exception ex = pae.getException();
            if (ex instanceof ClassNotFoundException) {
                throw (ClassNotFoundException) ex;
            }
            throw new RuntimeException(ex);
        }
    }

}
