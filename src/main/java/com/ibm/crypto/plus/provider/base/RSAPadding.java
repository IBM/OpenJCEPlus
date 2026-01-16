/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.security.spec.MGF1ParameterSpec;

public final class RSAPadding implements Cloneable {

    public static final int RSAPAD_NONE = 0;
    public static final int RSAPAD_PKCS1 = 1;
    public static final int RSAPAD_OAEP = 2;
    //private static final int RSA_SSLV23_PADDING // Unused?
    //private static final int RSA_X931_PADDING // Unused?
    //private static final int RSA_PKCS1_PSS_PADDING // Unused?

    public static final int NONE = 0;
    public static final int SHA1 = 1;
    public static final int SHA224 = 2;
    public static final int SHA256 = 3;
    public static final int SHA384 = 4;
    public static final int SHA512 = 5;
    public static final int SHA512_224 = 6;
    public static final int SHA512_256 = 7;

    private int id;
    private int md;
    private int mgf1;
    private String description;

    public static RSAPadding NoPadding() {
        return new RSAPadding(RSAPAD_NONE, NONE, NONE, "NoPadding");
    }

    public static RSAPadding PKCS1Padding() {
        return new RSAPadding(RSAPAD_PKCS1, NONE, NONE, "PKCS1Padding");
    }

    public static RSAPadding OAEPPadding() {
        return new RSAPadding(RSAPAD_OAEP, SHA1, SHA1, "OAEPPadding");
    }

    public static RSAPadding OAEPPaddingSHA224() {
        return new RSAPadding(RSAPAD_OAEP, SHA224, SHA1, "OAEPPadding");
    }

    public static RSAPadding OAEPPaddingSHA256() {
        return new RSAPadding(RSAPAD_OAEP, SHA256, SHA1, "OAEPPadding");
    }

    public static RSAPadding OAEPPaddingSHA384() {
        return new RSAPadding(RSAPAD_OAEP, SHA384, SHA1, "OAEPPadding");
    }

    public static RSAPadding OAEPPaddingSHA512() {
        return new RSAPadding(RSAPAD_OAEP, SHA512, SHA1, "OAEPPadding");
    }

    public static RSAPadding OAEPPaddingSHA512_224() {
        return new RSAPadding(RSAPAD_OAEP, SHA512_224, SHA1, "OAEPPadding");
    }

    public static RSAPadding OAEPPaddingSHA512_256() {
        return new RSAPadding(RSAPAD_OAEP, SHA512_256, SHA1, "OAEPPadding");
    }

    private RSAPadding(int id, int md, int mgf1, String description) {
        this.id = id;
        this.md = md;
        this.mgf1 = mgf1;
        this.description = description;
    }

    public int getId() {
        return this.id;
    }

    public boolean isPadding(int paddingId) {
        return (this.id == paddingId);
    }

    public void setMessageDigest(String mdName) {
        this.md = getIdFromName(mdName);
    }

    public int getMessageDigest() {
        return this.md;
    }

    public void setMGF1Digest(MGF1ParameterSpec spec) {
        if (spec != null) {
            this.mgf1 = getIdFromName(spec.getDigestAlgorithm());
        }
    }

    public int getMGF1Digest() {
        return this.mgf1;
    }

    public String toString() {
        return description;
    }

    private int getIdFromName(String name) {
        switch (name) {
            case "SHA-1":
            case "SHA1":
                return SHA1;
            case "SHA-224":
            case "SHA224":
                return SHA224;
            case "SHA-256":
            case "SHA256":
                return SHA256;
            case "SHA-384":
            case "SHA384":
                return SHA384;
            case "SHA-512":
            case "SHA512":
                return SHA512;
            case "SHA-512/224":
            case "SHA512/224":
                return SHA512_224;
            case "SHA-512/256":
            case "SHA512/256":
                return SHA512_256;
            default:
                return NONE;
        }
    }
}
