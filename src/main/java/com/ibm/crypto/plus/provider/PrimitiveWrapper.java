/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * This class is used by some algorithms that use the cleaner to clean up
 * native resources. Primitive type variables are passed by value instead
 * of reference as parameters. There are some cases where a primitive member
 * variable is modified after registering the instance to the cleaner, in 
 * which case the cleaner may not have the updated value of the variable.
 * To handle this scenario, one of the inner classes of PrimitiveWrapper 
 * is used to allow the passing of a primitive variable by reference.
 */

public final class PrimitiveWrapper {
    public static class Long { 
        long value;
        public Long(long value) {
            this.value = value;
        }

        public long getValue(){
            return this.value;
        }

        public void setValue(long value) {
            this.value = value;
        }
    }

    public static class Bool {
        boolean value;
        public Bool(boolean value) {
            this.value = value;
        }

        public boolean getValue(){
            return this.value;
        }

        public void setValue(boolean value) {
            this.value = value;
        }
    }
}
