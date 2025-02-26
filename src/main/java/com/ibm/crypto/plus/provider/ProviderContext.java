/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.Serializable;

// This class is used as a means of serializing information about the 
// OpenJCEPlus provider and being able to re-obtain the provider 
// reference during deserialization
//
@SuppressWarnings("serial")
abstract class ProviderContext implements Serializable {
    // Get the associated provider for this context
    //
    abstract OpenJCEPlusProvider getProvider();
}
