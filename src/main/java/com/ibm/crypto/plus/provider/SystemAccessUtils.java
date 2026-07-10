/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Utility methods for running privileged operations needed during provider
 * initialisation on Java versions that still have a SecurityManager
 * (i.e. Java &lt; 25).
 *
 * <p>All operations are unconditionally wrapped in
 * {@code AccessController.doPrivileged} so that they succeed even when the
 * calling thread does not hold the required permission.
 *
 * <p>Callers compose their own lambda, for example:
 * <pre>
 *   String home = SystemAccessUtils.doPrivileged(() -&gt; System.getProperty("java.home"));
 * </pre>
 */
public final class SystemAccessUtils {

    // Utility class – not instantiable.
    private SystemAccessUtils() {}

    /**
     * Run a value-returning action under {@code doPrivileged}.
     * Use this for actions that do not throw checked exceptions.
     *
     * @param <T>    the return type
     * @param action the action to run
     * @return the value returned by {@code action}
     */
    @SuppressWarnings({"removal", "restricted"})
    public static <T> T doPrivileged(Supplier<T> action) {
        return AccessController.doPrivileged((PrivilegedAction<T>) action::get);
    }

    /**
     * Run a value-returning action under {@code doPrivileged}.
     * Use this for actions that throw checked exceptions.
     *
     * @param <T>    the return type
     * @param action the action to run
     * @return the value returned by {@code action}
     * @throws Exception any checked exception thrown by {@code action}
     */
    @SuppressWarnings("removal")
    public static <T> T doPrivilegedChecked(Callable<T> action) throws Exception {
        try {
            return AccessController.doPrivileged(
                    (java.security.PrivilegedExceptionAction<T>) action::call);
        } catch (java.security.PrivilegedActionException pae) {
            throw pae.getException();
        }
    }

    /**
     * Run a void action under {@code doPrivileged}.
     *
     * @param action the action to run
     */
    @SuppressWarnings("removal")
    public static void runPrivileged(Runnable action) {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            action.run();
            return null;
        });
    }
}
