/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

module openjceplus {
    requires java.logging;
    requires jdk.unsupported;

    exports ibm.security.internal.spec;
    exports com.ibm.crypto.plus.provider;

    provides java.security.Provider with com.ibm.crypto.plus.provider.OpenJCEPlus;
}
