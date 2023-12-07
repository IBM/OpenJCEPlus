/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
