/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.certificateutils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import sun.security.x509.X509Key;

/**
 * Generate a pair of keys, and provide access to them. This class is provided
 * primarily for ease of use.
 *
 * <P>
 * This provides some simple certificate management functionality. Specifically,
 * it allows you to create self-signed X.509 certificates as well as PKCS 10
 * based certificate signing requests.
 *
 * <P>
 * Keys for some public key signature algorithms have algorithm parameters, such
 * as DSS/DSA. Some sites' Certificate Authorities adopt fixed algorithm
 * parameters, which speeds up some operations including key generation and
 * signing. <em>At this time, this interface
 * does not provide a way to provide such algorithm parameters, e.g.
 * by providing the CA certificate which includes those parameters.</em>
 *
 * <P>
 * Also, note that at this time only signature-capable keys may be acquired
 * through this interface. Diffie-Hellman keys, used for secure key exchange,
 * may be supported later.
 */

public final class CertAndKeyGen {

    private SecureRandom prng;
    private String sigAlg;
    private KeyPairGenerator keyGen;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String provider = null;

    private static Debug debug = Debug.getInstance("jceplus");
    private static String className = "ibm.jceplus.junit.base.certificateutils.CertAndKeyGen";

    /**
     * Creates a CertAndKeyGen object for a particular key type and signature
     * algorithm.
     *
     * @param keyType
     *            type of key, e.g. "RSA", "DSA"
     * @param sigAlg
     *            name of the signature algorithm, e.g. "MD5WithRSA",
     *            "MD2WithRSA", "SHAwithDSA".
     * @exception NoSuchAlgorithmException
     *                on unrecognized algorithms.
     */
    public CertAndKeyGen(String keyType, String sigAlg) throws NoSuchAlgorithmException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertAndKeyGen", keyType, sigAlg);
        }
        keyGen = KeyPairGenerator.getInstance(keyType);
        this.sigAlg = sigAlg;

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "CertAndKeyGen");
        }
    }

    /**
     * Creates a CertAndKeyGen object for a particular key type, signature
     * algorithm and the provider to get it from.
     *
     * @param keyType
     *            type of key, e.g. "RSA", "DSA"
     * @param sigAlg
     *            name of the signature algorithm, e.g. "MD5WithRSA",
     *            "MD2WithRSA", "SHAwithDSA".
     * @param provider
     *            name of the provider to supply the signature algorithm, and
     *            the keypairgenerator.
     * @exception NoSuchAlgorithmException
     *                on unrecognized algorithms.
     * @exception NoSuchProviderException
     *                on unrecognized provider names.
     */
    public CertAndKeyGen(String keyType, String sigAlg, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (debug != null) {
            Object[] parms = {keyType, sigAlg, provider};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertAndKeyGen", parms);
        }
        if (provider != null) {
            this.provider = new String(provider);
            keyGen = KeyPairGenerator.getInstance(keyType, provider);
        } else {
            keyGen = KeyPairGenerator.getInstance(keyType);
        }
        this.sigAlg = sigAlg;

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "CertAndKeyGen");
        }
    }

    /**
     * Sets the source of random numbers used when generating keys. If you do
     * not provide one, a system default facility is used. You may wish to
     * provide your own source of random numbers to get a reproducible sequence
     * of keys and signatures, or because you may be able to take advantage of
     * strong sources of randomness/entropy in your environment.
     */
    public void setRandom(SecureRandom generator) {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "setRandom", generator);
            debug.exit(Debug.TYPE_PUBLIC, className, "setRandom");
        }
        prng = generator;
    }

    // want "public void generate (X509Certificate)" ... inherit DSA/D-H param

    /**
     * Generates a random public/private key pair, with a given key size.
     * Different algorithms provide different degrees of security for the same
     * key size, because of the "work factor" involved in brute force attacks.
     * As computers become faster, it becomes easier to perform such attacks.
     * Small keys are to be avoided.
     *
     * <P>
     * Note that not all values of "keyBits" are valid for all algorithms, and
     * not all public key algorithms are currently supported for use in X.509
     * certificates. If the algorithm you specified does not produce X.509
     * compatible keys, an invalid key exception is thrown.
     *
     * @param keyBits
     *            the number of bits in the keys.
     * @exception InvalidKeyException
     *                if the environment does not provide X.509 public keys for
     *                this signature algorithm.
     */
    public void generate(int keyBits) throws InvalidKeyException {
        KeyPair pair;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "generate", keyBits);
        }
        try {
            if (prng == null)
                prng = new SecureRandom();
            keyGen.initialize(keyBits, prng);
            pair = keyGen.generateKeyPair();

        } catch (Exception e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "generate", e);
            }
            throw new IllegalArgumentException(e.getMessage());
        }

        publicKey = pair.getPublic();
        privateKey = pair.getPrivate();

        // This breaks our pkcs11Impl provider.
        // ----------------------------------------
        // publicKey's format must be X.509 otherwise
        // the whole CertGen part of this class is broken.

        // if (!"X.509".equalsIgnoreCase(publicKey.getFormat())) {
        // throw new IllegalArgumentException("publicKey's is not X.509, but "
        // + publicKey.getFormat());
        // }
        // ----------------------------------------
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "generate");
        }
    }

    /**
     * Generates a random public/private key pair, with the given
     * AlgoritmParameterSpec for that key Algorithm. Different algorithms
     * provide different degrees of security for the same key size, because of
     * the "work factor" involved in brute force attacks. As computers become
     * faster, it becomes easier to perform such attacks. Small keys are to be
     * avoided.
     *
     * <P>
     * Note that the AlgorithmParameterSpec must match the one needed to
     * generate keys for the specified algorithm. Not all public key algorithms
     * are currently supported for use in X.509 certificates. If the algorithm
     * you specified does not produce X.509 compatible keys, an invalid key
     * exception is thrown.
     *
     * @param params
     *            the Algorithm parameters needed to create a key pair.
     * @exception InvalidKeyException
     *                if the environment does not provide X.509 public keys for
     *                this signature algorithm.
     */
    public void generate(AlgorithmParameterSpec params) throws InvalidKeyException {
        KeyPair pair;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "generate", params);
        }
        try {
            if (prng == null) {
                prng = new SecureRandom();
            }

            keyGen.initialize(params, prng);
            pair = keyGen.generateKeyPair();

        } catch (Exception e) {

            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "generate", e);
            }
            throw new IllegalArgumentException(e.getMessage());
        }

        publicKey = pair.getPublic();
        privateKey = pair.getPrivate();

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "generate");
        }
    }

    /**
     * Returns the public key of the generated key pair if it is of type
     * <code>X509Key</code>, or null if the public key is of a different type.
     *
     * XXX Note: This behaviour is needed for backwards compatibility. What this
     * method really should return is the public key of the generated key pair,
     * regardless of whether or not it is an instance of <code>X509Key</code>.
     * Accordingly, the return type of this method should be
     * <code>PublicKey</code>.
     */
    public X509Key getPublicKey() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getPublicKey");
        }
        if (!(publicKey instanceof X509Key)) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getPublicKey_1", null);
            }
            return (null);
        }
        // LOCKDOWN Okay to return reference since PublicKeys are immutable.
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getPublicKey_2", (X509Key) publicKey);
        }
        return (X509Key) publicKey;
    }

    /**
     * Always returns the public key of the generated key pair. Used by KeyTool
     * only.
     *
     * The publicKey is not necessarily to be an instance of X509Key in some
     * JCA/JCE providers, for example SunPKCS11.
     */
    public PublicKey getPublicKeyAnyway() {
        return publicKey;
    }

    public Key newGetPublicKey() {
        // LOCKDOWN Okay to return reference since PublicKeys are immutable.
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "newGetPublicKey");
            debug.exit(Debug.TYPE_PUBLIC, className, "newGetPublicKey", publicKey);
        }
        return (publicKey);
    }

    /**
     * Returns the private key of the generated key pair.
     *
     * <P>
     * <STRONG><em>Be extremely careful when handling private keys.
     * When private keys are not kept secret, they lose their ability
     * to securely authenticate specific entities ... that is a huge
     * security risk!</em></STRONG>
     */
    public PrivateKey getPrivateKey() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getPrivateKey");
            debug.exit(Debug.TYPE_PUBLIC, className, "getPrivateKey", privateKey);
        }
        return (privateKey);
    }

    /**
     * Returns the key generator used to generate the public and private keys.
     */
    public KeyPairGenerator getKeyPairGenerator() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getKeyPairGenerator");
            debug.exit(Debug.TYPE_PUBLIC, className, "getKeyPairGenerator", keyGen);
        }
        return (keyGen);
    }

    /**
     * Returns a self-signed X.509v1 certificate for the public key. The
     * certificate is immediately valid.
     *
     * <P>
     * Such certificates normally are used to identify a "Certificate Authority"
     * (CA). Accordingly, they will not always be accepted by other parties.
     * However, such certificates are also useful when you are bootstrapping
     * your security infrastructure, or deploying system prototypes.
     *
     *
     * @param myname
     *            X.500 name of the subject (who is also the issuer)
     * @param validity
     *            how long the certificate should be valid, in seconds
     */
    public X509Certificate getSelfCert(X500Name myname, long validity)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException {


        X500Signer issuer;
        X509CertImpl cert;
        Date firstDate, lastDate;

        try {
            if (debug != null) {
                Object[] parms = {myname, validity};
                debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCert", parms);
            }
            issuer = getSigner2(myname);

            firstDate = new Date();
            lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + validity * 1000);
            checkValidityDate(lastDate);

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            // Note here that V1 = 0, V2 = 1, V3 = 2
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));


            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber((int) (firstDate.getTime() / 1000)));
            AlgorithmId algID = issuer.getAlgorithmId();
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            //info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(myname));
            info.set(X509CertInfo.SUBJECT, myname);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VALIDITY, interval);
            //            info.set(X509CertInfo.ISSUER,
            //                     new CertificateIssuerName(issuer.getSigner()));
            info.set(X509CertInfo.ISSUER, issuer.getSigner());

            cert = new X509CertImpl(info);
            // 991119 - Updated to match JDK 1.2.2 source.
            //cert.sign(privateKey, algID.getName());
            //cert.sign(privateKey, this.sigAlg);
            if (provider == null) {
                cert.sign(privateKey, this.sigAlg);
            } else {
                cert.sign(privateKey, this.sigAlg, provider);
            }

            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCert", (X509Certificate) cert);
            }
            return (X509Certificate) cert;

        } catch (IOException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getSelfCert", e);
            }
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    public X509Certificate getSelfCert(X500Name myname, long validity,
            AlgorithmParameterSpec sigParameterSpec)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return dogetSelfCert(myname, validity, sigParameterSpec);
    }

    public X509Certificate dogetSelfCert(X500Name myname, long validity,
            AlgorithmParameterSpec sigParameterSpec)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        X500Signer issuer;
        X509CertImpl cert;
        Date firstDate, lastDate;

        try {
            if (debug != null) {
                Object[] parms = {myname, validity, sigParameterSpec};
                debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCert", parms);
            }
            issuer = getSigner2(myname, sigParameterSpec);

            firstDate = new Date();
            lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + validity * 1000);
            checkValidityDate(lastDate);

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            // Note here that V1 = 0, V2 = 1, V3 = 2
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber((int) (firstDate.getTime() / 1000)));
            AlgorithmId algID = issuer.getAlgorithmId();
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            // info.set(X509CertInfo.SUBJECT, new
            // CertificateSubjectName(myname));
            info.set(X509CertInfo.SUBJECT, myname);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VALIDITY, interval);
            // info.set(X509CertInfo.ISSUER,
            // new CertificateIssuerName(issuer.getSigner()));
            info.set(X509CertInfo.ISSUER, issuer.getSigner());

            cert = new X509CertImpl(info);
            // 991119 - Updated to match JDK 1.2.2 source.
            // cert.sign(privateKey, algID.getName());
            // cert.sign(privateKey, this.sigAlg);
            if (provider == null) {
                cert.sign(privateKey, this.sigAlg);
            } else {
                cert.sign(privateKey, this.sigAlg, provider);
            }

            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCert", (X509Certificate) cert);
            }
            return (X509Certificate) cert;

        } catch (IOException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getSelfCert", e);
            }
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    /**
     * Returns a self-signed X.509v3 certificate for the public key. The
     * certificate is immediately valid. No extensions.
     *
     * <P>
     * Such certificates normally are used to identify a "Certificate Authority"
     * (CA). Accordingly, they will not always be accepted by other parties.
     * However, such certificates are also useful when you are bootstrapping
     * your security infrastructure, or deploying system prototypes.
     *
     * @param myname
     *            X.500 name of the subject (who is also the issuer)
     * @param validity
     *            how long the certificate should be valid, in seconds
     * @exception CertificateException
     *                on certificate handling errors.
     * @exception InvalidKeyException
     *                on key handling errors.
     * @exception SignatureException
     *                on signature handling errors.
     * @exception NoSuchAlgorithmException
     *                on unrecognized algorithms.
     * @exception NoSuchProviderException
     *                on unrecognized providers.
     */
    public X509Certificate getSelfCertificate(X500Name myname, long validity)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCertificate", myname, validity);
            debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCertificate",
                    getSelfCertificate(myname, validity, CertificateVersion.V3));
        }
        return (getSelfCertificate(myname, validity, CertificateVersion.V3));
    }

    /**
     * Returns a self-signed X.509 certificate with a specifed version for the
     * public key. The certificate is immediately valid. No extensions.
     *
     * <P>
     * Such certificates normally are used to identify a "Certificate Authority"
     * (CA). Accordingly, they will not always be accepted by other parties.
     * However, such certificates are also useful when you are bootstrapping
     * your security infrastructure, or deploying system prototypes.
     *
     * @param myname
     *            X.500 name of the subject (who is also the issuer)
     * @param validity
     *            how long the certificate should be valid, in seconds
     * @param version
     *            Certificate version. Valid values are 0 to 2.
     * @exception CertificateException
     *                on certificate handling errors.
     * @exception InvalidKeyException
     *                on key handling errors.
     * @exception SignatureException
     *                on signature handling errors.
     * @exception NoSuchAlgorithmException
     *                on unrecognized algorithms.
     * @exception NoSuchProviderException
     *                on unrecognized providers.
     */

    // Same as the above method, but this accepts the version as a parameter
    // rather than setting a default.
    public X509Certificate getSelfCertificate(X500Name myname, long validity, int version)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException {
        X500Signer issuer;
        X509CertImpl cert;
        Date firstDate, lastDate;

        try {
            if (debug != null) {
                Object[] parms = {myname, validity, version};
                debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCertificate", parms);
            }
            issuer = getSigner(myname);

            firstDate = new Date();
            lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + validity * 1000);
            checkValidityDate(lastDate);

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            // Note here that V1 = 0, V2 = 1, V3 = 2
            if ((version != CertificateVersion.V1) && (version != CertificateVersion.V2)
                    && (version != CertificateVersion.V3)) {
                info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            } else {
                info.set(X509CertInfo.VERSION, new CertificateVersion(version));
            }

            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber((int) (firstDate.getTime() / 1000)));
            AlgorithmId algID = issuer.getAlgorithmId();
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            info.set(X509CertInfo.SUBJECT, myname);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.ISSUER, issuer.getSigner());

            cert = new X509CertImpl(info);
            // 991119 - Updated to match JDK 1.2.2 source.
            // cert.sign(privateKey, algID.getName());
            // cert.sign(privateKey, this.sigAlg);
            if (provider == null) {
                cert.sign(privateKey, this.sigAlg);
            } else {
                cert.sign(privateKey, this.sigAlg, provider);
            }

            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCertificate",
                        (X509Certificate) cert);
            }
            return (X509Certificate) cert;

        } catch (IOException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getSelfCertificate", e);
            }
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    /**
     * Returns a self-signed X.509 certificate with a specifed version for the
     * public key. The certificate is immediately valid. No extensions.
     *
     * <P>
     * Such certificates normally are used to identify a "Certificate Authority"
     * (CA). Accordingly, they will not always be accepted by other parties.
     * However, such certificates are also useful when you are bootstrapping
     * your security infrastructure, or deploying system prototypes.
     *
     * @param myname
     *            X.500 name of the subject (who is also the issuer)
     * @param validity
     *            how long the certificate should be valid, in seconds
     * @param version
     *            Certificate version. Valid values are 0 to 2.
     * @exception CertificateException
     *                on certificate handling errors.
     * @exception InvalidKeyException
     *                on key handling errors.
     * @exception SignatureException
     *                on signature handling errors.
     * @exception NoSuchAlgorithmException
     *                on unrecognized algorithms.
     * @exception NoSuchProviderException
     *                on unrecognized providers.
     */

    // Same as the above method, but this accepts the version as a parameter
    // rather than setting a default.
    public X509Certificate getSelfCertificate(X500Name myname, long validity, int version,
            AlgorithmParameterSpec sigAlgParamSpec)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        X500Signer issuer;
        X509CertImpl cert;
        Date firstDate, lastDate;

        try {
            if (debug != null) {
                Object[] parms = {myname, validity, version};
                debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCertificate", parms);
            }
            issuer = getSigner(myname, sigAlgParamSpec);

            firstDate = new Date();
            lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + validity * 1000);
            checkValidityDate(lastDate);

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            // Note here that V1 = 0, V2 = 1, V3 = 2
            if ((version != CertificateVersion.V1) && (version != CertificateVersion.V2)
                    && (version != CertificateVersion.V3)) {
                info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            } else {
                info.set(X509CertInfo.VERSION, new CertificateVersion(version));
            }

            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber((int) (firstDate.getTime() / 1000)));
            AlgorithmId algID = issuer.getAlgorithmId();
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            info.set(X509CertInfo.SUBJECT, myname);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.ISSUER, issuer.getSigner());

            cert = new X509CertImpl(info);
            // 991119 - Updated to match JDK 1.2.2 source.
            // cert.sign(privateKey, algID.getName());
            // cert.sign(privateKey, this.sigAlg);
            if (provider == null) {
                cert.sign(privateKey, this.sigAlg);
            } else {
                cert.sign(privateKey, this.sigAlg, provider);
            }

            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCertificate",
                        (X509Certificate) cert);
            }
            return (X509Certificate) cert;

        } catch (IOException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getSelfCertificate", e);
            }
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    /**
     * Returns a self-signed X.509v3 certificate for the public key. The
     * certificate is immediately valid. No extensions.
     *
     * <P>
     * Such certificates normally are used to identify a "Certificate Authority"
     * (CA). Accordingly, they will not always be accepted by other parties.
     * However, such certificates are also useful when you are bootstrapping
     * your security infrastructure, or deploying system prototypes.
     *
     * @param myname
     *            X.500 name of the subject (who is also the issuer)
     * @param firstDate
     *            the issue time of the certificate
     * @param validity
     *            how long the certificate should be valid, in seconds
     * @exception CertificateException
     *                on certificate handling errors.
     * @exception InvalidKeyException
     *                on key handling errors.
     * @exception SignatureException
     *                on signature handling errors.
     * @exception NoSuchAlgorithmException
     *                on unrecognized algorithms.
     * @exception NoSuchProviderException
     *                on unrecognized providers.
     */
    public X509Certificate getSelfCertificate(X500Name myname, Date firstDate, long validity)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException {
        return getSelfCertificate(myname, firstDate, validity, null);
    }

    // Like above, plus a CertificateExtensions argument, which can be null.
    public X509Certificate getSelfCertificate(X500Name myname, Date firstDate, long validity,
            CertificateExtensions ext) throws CertificateException, InvalidKeyException,
            SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        X509CertImpl cert;
        Date lastDate;

        try {
            if (debug != null) {
                Object[] parms = {myname, firstDate, validity};
                debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCertificate", parms);
            }
            lastDate = new Date();
            lastDate.setTime(firstDate.getTime() + validity * 1000);
            checkValidityDate(lastDate);

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
            AlgorithmId algID = AlgorithmId.get(sigAlg);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            info.set(X509CertInfo.SUBJECT, myname);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.ISSUER, myname);
            if (ext != null)
                info.set(X509CertInfo.EXTENSIONS, ext);

            cert = new X509CertImpl(info);
            cert.sign(privateKey, this.sigAlg);
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCertificate",
                        (X509Certificate) cert);
            }
            return (X509Certificate) cert;

        } catch (IOException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getSelfCertificate", e);
            }
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    public X509Certificate dogetSelfCertificate(X500Name myname, Date firstDate, long validity,
            CertificateExtensions ext)
            throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        X509CertImpl cert;
        Date lastDate;

        try {
            if (debug != null) {
                Object[] parms = {myname, firstDate, validity};
                debug.entry(Debug.TYPE_PUBLIC, className, "getSelfCertificate", parms);
            }
            lastDate = new Date();
            lastDate.setTime(firstDate.getTime() + validity * 1000);
            checkValidityDate(lastDate);

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
            AlgorithmId algID = AlgorithmId.get(sigAlg);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            info.set(X509CertInfo.SUBJECT, myname);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.ISSUER, myname);
            if (ext != null)
                info.set(X509CertInfo.EXTENSIONS, ext);

            cert = new X509CertImpl(info);
            cert.sign(privateKey, this.sigAlg);
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSelfCertificate",
                        (X509Certificate) cert);
            }
            return (X509Certificate) cert;

        } catch (IOException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getSelfCertificate", e);
            }
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    /*
     * Returns a PKCS #10 certificate request. The caller uses either
     * <code>PKCS10.print</code> or <code>PKCS10.toByteArray</code> operations
     * on the result, to get the request in an appropriate transmission format.
     * 
     * <P>PKCS #10 certificate requests are sent, along with some proof of
     * identity, to Certificate Authorities (CAs) which then issue X.509 public
     * key certificates.
     * 
     * @param myname X.500 name of the subject
     * 
     * @exception InvalidKeyException on key handling errors.
     * 
     * @exception SignatureException on signature handling errors.
     */
    public CertificationRequest getCertRequest(X500Name myname) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, IllegalArgumentException, IOException {

        CertificationRequest req, req2;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getCertRequest", myname);
        }
        CertificationRequestInfo cri = new CertificationRequestInfo(myname, publicKey, null,
                this.provider);
        req = new CertificationRequest(cri, this.provider);

        try {
            req2 = req.sign(sigAlg, privateKey);
        } catch (PKCSException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "getCertRequest", e);
            }
            throw new SignatureException(sigAlg + " PKCSException");
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getCertRequest", req2);
        }
        return (req2);
    }

    private X500Signer getSigner(X500Name me)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = null;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSigner", me);
        }
        // XXX should have a way to pass prng to the signature
        // algorithm ... appropriate for DSS/DSA, not RSA

        if (this.provider != null) {
            signature = Signature.getInstance(sigAlg, this.provider);
        } else {
            signature = Signature.getInstance(sigAlg);
        }
        signature.initSign(privateKey);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSigner", new X500Signer(signature, me));
        }
        return (new X500Signer(signature, me));
    }

    /**
     * Same as above except accepts parameters for signature algorithms
     */
    private X500Signer getSigner(X500Name me, AlgorithmParameterSpec sigParameterSpec)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        Signature signature = null;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSigner",
                    new Object[] {me, sigParameterSpec});
        }
        // XXX should have a way to pass prng to the signature
        // algorithm ... appropriate for DSS/DSA, not RSA

        if (this.provider != null) {
            signature = Signature.getInstance(sigAlg, this.provider);
        } else {
            signature = Signature.getInstance(sigAlg);
        }
        if (sigParameterSpec != null)
            signature.setParameter(sigParameterSpec);
        signature.initSign(privateKey);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSigner", new X500Signer(signature, me));
        }
        return (new X500Signer(signature, me, sigParameterSpec));
    }

    // difference of getSigner2 from getSigner is it doesn't initialize
    // signature
    private X500Signer getSigner2(X500Name me)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature signature = null;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSigner", me);
        }
        // XXX should have a way to pass prng to the signature
        // algorithm ... appropriate for DSS/DSA, not RSA

        if (this.provider != null) {
            signature = Signature.getInstance(sigAlg, this.provider);
        } else {
            signature = Signature.getInstance(sigAlg);
        }
        // signature.initSign(privateKey);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSigner", new X500Signer(signature, me));
        }
        return (new X500Signer(signature, me));
    }

    // difference of getSigner2 from getSigner is it doesn't initialize
    // signature
    private X500Signer getSigner2(X500Name me, AlgorithmParameterSpec sigParameterSpec)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        Signature signature = null;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSigner",
                    new Object[] {me, sigParameterSpec});
        }
        // XXX should have a way to pass prng to the signature
        // algorithm ... appropriate for DSS/DSA, not RSA

        if (this.provider != null) {
            signature = Signature.getInstance(sigAlg, this.provider);
        } else {
            signature = Signature.getInstance(sigAlg);
        }
        if (sigParameterSpec != null)
            signature.setParameter(sigParameterSpec);

        // signature.initSign(privateKey);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSigner", new X500Signer(signature, me));
        }
        return (new X500Signer(signature, me, sigParameterSpec));
    }

    private static void checkValidityDate(Date lastDate) throws CertificateException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PRIVATE, className, "checkValidityDate", lastDate);
        }
        Calendar c = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        c.setTime(lastDate);
        if (c.get(Calendar.YEAR) > 9999) {
            throw new CertificateException("Validity period ends at calendar year "
                    + c.get(Calendar.YEAR) + " which is greater than 9999");
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PRIVATE, className, "checkValidityDate", lastDate);
        }
    }
}
