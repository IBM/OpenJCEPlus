/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import junit.framework.TestCase;

public class BaseTestInterop extends TestCase {
    //--------------------------------------------------------------------------
    //
    //
    protected String providerName;
    protected String interopProviderName;


    //--------------------------------------------------------------------------
    //
    //
    public BaseTestInterop(String providerName, String interopProviderName) {
        this.providerName = providerName;
        this.interopProviderName = interopProviderName;
    }
}

