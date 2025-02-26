/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


/*From section 9.11 of GSKit_crypto.pdf 
RSA keys contain a lot of internal state, and if a single key is used for multiple purposes (sign/verify with different
algorithms) encrypt/decrypt retained internal state changes may make subsequent operations fail unexpectedly.

Note that the multiple role use of RSA keys is now explicitly forbidden in the FIPS 186-4 standard.

Threaded performance can also be a significant issue, RSA keys contain dynamic data (i.e. blinding structures) and
while OpenSSL will lock to protect this, this will serialize RSA operations across threads - with sometimes significant
performance hits.

Use ICC_RSA_PRivateKey_dup() to clone keys where this may be a problem.

This is not an issue when the key is used repeatedly for a single mode of operation in a single thread i.e. Sign/Verify
with the same algorithm or Encrypt/Decrypt.

The maximum size of the exponent used in RSA calculations is limited to a number that can be held in an unsigned
long. This limitation should never be hit in practice. (The typical RSA exponent used is 65537).*/

/* Why the synchronization in this class was not done in the original release is not clear.
 *  As part of fixing the segmentation fault in WAS Commerce Server which runs with multiple threads, synchronization was added to
 *  encrypt/decrypt methods. If performance degradation due to synchronization becomes significant, we may have to revisit this decision.*/


public final class RSACipher {

    private OCKContext ockContext = null;
    private RSAKey rsaKey = null;
    private final String badIdMsg = "RSA Key Identifier is not valid";
    private boolean convertKey = false; //Used to convert RSA Plain keys
    // private final String debPrefix = "RSACipher"; /* Adding DEBUG messes up encrypt/decrypt cases */

    public static RSACipher getInstance(OCKContext ockContext) {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        return new RSACipher(ockContext);
    }

    private RSACipher(OCKContext ockContext) {
        this.ockContext = ockContext;
    }

    public void initialize(RSAKey key, boolean plainRSAKey)
            throws OCKException, InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key is null");
        }
        this.rsaKey = key;
        this.convertKey = plainRSAKey;
    }

    // Method not synchronized since ObtainKeySize method used getKeySize is synchronized 
    //
    public int getOutputSize() throws OCKException {
        checkInitialized();
        return this.rsaKey.getKeySize();
    }

    public synchronized int publicEncrypt(RSAPadding padding, byte[] input, int inOffset, int inLen,
            byte[] output, int outOffset) throws BadPaddingException, IllegalBlockSizeException,
            ShortBufferException, OCKException {
        checkInitialized();
        if (inLen == 0)
            return 0;
        checkInputRange(input, inOffset, inLen);
        checkOutputRange(output, outOffset);
        if (!validId(this.rsaKey.getRSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        return checkOutLen(NativeInterface.RSACIPHER_public_encrypt(this.ockContext.getId(),
                this.rsaKey.getRSAKeyId(), padding.getId(), input, inOffset, inLen, output,
                outOffset));
    }

    public synchronized int privateEncrypt(RSAPadding padding, byte[] input, int inOffset,
            int inLen, byte[] output, int outOffset) throws BadPaddingException,
            IllegalBlockSizeException, ShortBufferException, OCKException {
        checkInitialized();
        if (inLen == 0)
            return 0;
        checkInputRange(input, inOffset, inLen);
        checkOutputRange(output, outOffset);
        if (!validId(this.rsaKey.getRSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        return checkOutLen(NativeInterface.RSACIPHER_private_encrypt(this.ockContext.getId(),
                this.rsaKey.getRSAKeyId(), padding.getId(), input, inOffset, inLen, output,
                outOffset, convertKey));
    }

    public synchronized int publicDecrypt(RSAPadding padding, byte[] input, int inOffset, int inLen,
            byte[] output, int outOffset) throws BadPaddingException, IllegalBlockSizeException,
            ShortBufferException, OCKException {
        checkInitialized();
        if (inLen == 0)
            return 0;
        checkInputRange(input, inOffset, inLen);
        checkOutputRange(output, outOffset);
        if (inLen != getOutputSize()) {
            throw new IllegalBlockSizeException(
                    "Input must be: " + getOutputSize() + " bytes long");
        }
        if (!validId(this.rsaKey.getRSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        return checkOutLen(NativeInterface.RSACIPHER_public_decrypt(this.ockContext.getId(),
                this.rsaKey.getRSAKeyId(), padding.getId(), input, inOffset, inLen, output,
                outOffset));
    }

    public synchronized int privateDecrypt(RSAPadding padding, byte[] input, int inOffset,
            int inLen, byte[] output, int outOffset) throws BadPaddingException,
            IllegalBlockSizeException, ShortBufferException, OCKException {
        checkInitialized();
        if (inLen == 0)
            return 0;
        checkInputRange(input, inOffset, inLen);
        checkOutputRange(output, outOffset);
        if (inLen != getOutputSize()) {
            throw new IllegalBlockSizeException(
                    "Input must be: " + getOutputSize() + " bytes long");
        }
        if (!validId(this.rsaKey.getRSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        return checkOutLen(NativeInterface.RSACIPHER_private_decrypt(this.ockContext.getId(),
                this.rsaKey.getRSAKeyId(), padding.getId(), input, inOffset, inLen, output,
                outOffset, convertKey));
    }

    private void checkInputRange(byte[] input, int offset, int length) {
        if (input == null || length < 0 || offset < 0 || (offset + length) > input.length) {
            throw new IllegalArgumentException("Input range is invalid");
        }
    }

    private void checkOutputRange(byte[] output, int offset)
            throws ShortBufferException, OCKException {
        if (output == null || (offset > output.length)
                || (output.length - offset) < getOutputSize()) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + getOutputSize() + " bytes long");
        }
        if (offset < 0) {
            throw new IllegalArgumentException("Output range is invalid");
        }
    }

    private void checkInitialized() {
        if (this.rsaKey == null) {
            throw new IllegalStateException("RSACipher is not initialized");
        }
    }

    private int checkOutLen(int outLen) throws BadPaddingException {
        if (outLen < 0) {
            throw new BadPaddingException("Decryption error");
        }
        return outLen;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }

}
