/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

module openjceplus {
    requires java.logging;
    requires jdk.unsupported;

    exports ibm.security.internal.spec;
    exports com.ibm.crypto.plus.provider;

    provides java.security.Provider with com.ibm.crypto.plus.provider.OpenJCEPlus;
}
