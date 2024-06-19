/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.certificateutils;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.Signer;
import java.security.spec.AlgorithmParameterSpec;
import com.ibm.misc.Debug;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

/**
 * This class provides a binding between a Signature object and an
 * authenticated X.500 name (from an X.509 certificate chain), which
 * is needed in many public key signing applications.
 *
 * <P>The name of the signer is important, both because knowing it is the
 * whole point of the signature, and because the associated X.509 certificate
 * is always used to verify the signature.
 *
 * <P><em>The X.509 certificate chain is temporarily not associated with
 * the signer, but this omission will be resolved.</em>
 *
 */

// LOCKDOWN make package protected
@SuppressWarnings("removal")
public class X500Signer extends Signer {

    static final long serialVersionUID = -7949587785526204490L;

    private transient Signature sig;
    private transient X500Name agent; // XXX should be X509CertChain
    private AlgorithmId algid;

    private static Debug debug = Debug.getInstance("jceplus");
    private static String className = "ibm.jceplus.junit.base.certificateutils.X500Signer";

    /**
     * Called for each chunk of the data being signed.  That
     * is, you can present the data in many chunks, so that
     * it doesn't need to be in a single sequential buffer.
     *
     * @param buf buffer holding the next chunk of the data to be signed
     * @param offset starting point of to-be-signed data
     * @param len how many bytes of data are to be signed
     * @exception SignatureException on errors.
     */
    public void update(byte buf[], int offset, int len) throws SignatureException {
        if (debug != null) {
            Object[] parms = {buf, offset, len};
            debug.entry(Debug.TYPE_PUBLIC, className, "update", parms);
        }
        sig.update(buf, offset, len);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "update");
        }
    }

    /**
     * Produces the signature for the data processed by update().
     *
     * @exception SignatureException on errors.
     */
    public byte[] sign() throws SignatureException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "sign");
        }
        byte[] result = sig.sign();
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "sign", result);
        }
        return result;
    }

    /**
     * Returns the algorithm used to sign.
     */
    public AlgorithmId getAlgorithmId() {
        // LOCKDOWN Okay to return reference; AlgorithmIds are immutable.
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getAlgorithmId");
            debug.exit(Debug.TYPE_PUBLIC, className, "getAlgorithmId", algid);
        }
        return algid;
    }

    /**
     * Returns the name of the signing agent.
     */
    public X500Name getSigner() {
        // LOCKDOWN Okay to return reference; X500Names are immutable.
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSigner");
            debug.exit(Debug.TYPE_PUBLIC, className, "getSigner", agent);
        }
        return agent;
    }

    /*
     * Constructs a binding between a signature and an X500 name
     * from an X.509 certificate.
     */
    // package private  ----hmmmmm ?????
    public X500Signer(Signature sig, X500Name agent) {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "X500Signer", sig, agent);
        }
        if (sig == null || agent == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "X500Signer", "null parameter");
            }
            throw new IllegalArgumentException("null parameter");
        }

        this.sig = sig;
        this.agent = agent;

        try {
            this.algid = AlgorithmId.get(sig.getAlgorithm());

        } catch (NoSuchAlgorithmException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "X500Signer", e);
                debug.text(Debug.TYPE_PUBLIC, className, "X500Signer",
                        "internal error! " + e.getMessage());
            }
            throw new RuntimeException("internal error! " + e.getMessage());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "X500Signer");
        }
    }

    /**
     * Take parameters for Signing algorithm
     */
    // package private  ----hmmmmm ?????
    public X500Signer(Signature sig, X500Name agent, AlgorithmParameterSpec sigParameterSpec) {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "X500Signer",
                    new Object[] {sig, agent, sigParameterSpec});
        }
        if (sig == null || agent == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "X500Signer", "null parameter");
            }
            throw new IllegalArgumentException("null parameter");
        }

        this.sig = sig;
        this.agent = agent;

        try {
            this.algid = AlgorithmId.get(sig.getParameters());

        } catch (NoSuchAlgorithmException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "X500Signer", e);
                debug.text(Debug.TYPE_PUBLIC, className, "X500Signer",
                        "internal error! " + e.getMessage());
            }
            throw new RuntimeException("internal error! " + e.getMessage());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "X500Signer");
        }
    }
}
