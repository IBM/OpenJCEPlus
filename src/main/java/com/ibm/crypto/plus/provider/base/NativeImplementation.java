/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.io.File;
import sun.security.util.Debug;

public abstract class NativeImplementation {
    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    @SuppressWarnings("restricted")
    protected static boolean loadIfExists(File libraryFile) {
        String libraryName = libraryFile.getAbsolutePath();
        System.out.println("Library name: " + libraryName);

        if (libraryFile.exists()) {
            // Need a try/catch block in case the library has already been
            // loaded by another ClassLoader
            //
            try {
                System.load(libraryName);
                System.out.println("Loaded");
                if (debug != null) {
                    debug.println("Loaded : " + libraryName);
                }
                return true;
            } catch (Throwable t) {
                System.out.println("Failed to load");
                if (debug != null) {
                    debug.println("Failed to load : " + libraryName);
                }
            }
        } else {
            System.out.println("Skipping load");
            if (debug != null) {
                debug.println("Skipping load of " + libraryName);
            }
        }
        return false;
    }
}
