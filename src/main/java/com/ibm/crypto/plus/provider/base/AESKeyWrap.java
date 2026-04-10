/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;
import java.util.Arrays;

public final class AESKeyWrap {

    private NativeInterface nativeInterface;
    private byte[] key = null;
    private boolean padding = false;

    public AESKeyWrap(OpenJCEPlusProvider provider, byte[] key, boolean padding)
            throws OCKException {
        if (key == null) {
            throw new OCKException("Invalid input data");
        }
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        this.key = key;
        this.padding = padding;
    }

    public byte[] wrap(byte[] data, int start, int length) throws OCKException {
        if (data == null || start < 0 || data.length < start || data.length < (length + start)) {
            throw new OCKException("Invalid input data");
        }
        byte[] output = null;
        byte[] inData = Arrays.copyOfRange(data, start, length);
        
        int type = 1; //wrap
        if (padding) {
            type = type | 4; // add padding
        }

        try {
            output = this.nativeInterface.CIPHER_KeyWraporUnwrap(inData, this.key, type);
        } catch (Exception e) {
            throw new OCKException("Failed to wrap data" + e.getMessage());
        }  finally {
            //Clear inData
            Arrays.fill(inData, (byte) 0);
        }
        return output;
    }

    public byte[] unwrap(byte[] data, int start, int length) throws OCKException {
        if (data == null || start < 0 || length < start || data.length < (length - start)) {
            throw new OCKException("Invalid input data");
        }
        byte[] output = null;
        byte[] inData = Arrays.copyOfRange(data, start, length);
        int type = 0;

        if (padding) {
            type = 4; // add padding
        }

        try {
            output = this.nativeInterface.CIPHER_KeyWraporUnwrap(inData, this.key, type);
        } catch (Exception e) {
            throw new OCKException("Failed to unwrap data" + e.getMessage());
        }  finally {
            //Clear inData
            Arrays.fill(inData, (byte) 0);
        }
        return output;
    }

}
