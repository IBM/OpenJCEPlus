/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.util.Arrays;

public final class AESKeyWrap {

    private OCKContext ockContext;
    private byte [] key = null;
    private boolean padding = false;

    public AESKeyWrap(OCKContext ockContext, byte [] key, boolean padding)
            throws OCKException {
        if (ockContext == null || key == null) {
            throw new OCKException("Invalid input data");
        }        
        this.ockContext = ockContext;
        this.key = key;
        this.padding = padding;
    }

    public byte [] wrap(byte [] data, int start, int length) throws OCKException {
        if (data == null || start < 0 || data.length < start || data.length < (length + start)) {
            throw new OCKException("Invalid input data");
        }
        byte [] output = null;
        byte [] inData = Arrays.copyOfRange(data, start, length);
        
        int type = 1; //wrap
        if (padding) {
            type = type|4; // add padding
        }

        try {
            output = NativeInterface.CIPHER_KeyWraporUnwrap(this.ockContext.getId(), inData, this.key, type);
        } catch (Exception e) {
            throw new OCKException("Failed to wrap data" + e.getMessage());
        }  finally {
            //Clear inData
            Arrays.fill(inData, (byte)0);  
        }   
        return output;    
    }

    public byte [] unwrap(byte [] data, int start, int length) throws OCKException {
        if (data == null || start < 0 || length < start || data.length < (length - start)) {
            throw new OCKException("Invalid input data");
        }
        byte [] output = null;
        byte [] inData = Arrays.copyOfRange(data, start, length);
        int type = 0;

        if (padding) {
            type = 4; // add padding
        }

        try {
            output = NativeInterface.CIPHER_KeyWraporUnwrap(this.ockContext.getId(), inData, this.key, type);
        } catch (Exception e) {
            throw new OCKException("Failed to unwrap data"+ e.getMessage());
        }  finally {
            //Clear inData
            Arrays.fill(inData, (byte)0);  
        }       
        return output;    
    }


}
