/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.Digest;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

/**
 * Composite signature engine for draft-ietf-lamps-pq-composite-sigs.
 *
 * <p>Each composite algorithm pairs an ML-DSA component with a traditional
 * component (ECDSA, RSA-PSS, RSA-PKCS1 or EdDSA). Signing runs both engines
 * over the domain-separated message and returns:
 *
 * <pre>
 * CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
 * </pre>
 *
 * <p>Verification decodes the SEQUENCE and succeeds only if <em>both</em>
 * component signatures are valid.
 *
 * <h2>Message representative (draft §2.2)</h2>
 * <p>Before passing to each sub-engine the message representative M' is formed as:
 * <pre>
 * M' = Prefix || Label || len(ctx) || ctx || PH( M )
 * </pre>
 * where {@code Prefix} is the fixed ASCII string
 * {@code "CompositeAlgorithmSignatures2025"}, {@code Label} is the
 * per-algorithm ASCII label (e.g. {@code "COMPSIG-MLDSA44-RSA2048-PSS-SHA256"}),
 * {@code ctx} defaults to an empty byte array, and {@code PH} is the
 * per-algorithm pre-hash function (SHA-256 or SHA-512).
 */
@SuppressWarnings("restriction")
abstract class CompositeSignatureImpl extends SignatureSpi {

    private static final byte[] DOMAIN_PREFIX =
            "CompositeAlgorithmSignatures2025".getBytes(StandardCharsets.US_ASCII);

    private final OpenJCEPlusProvider provider;
    private final String compositeAlg;
    private final String mldsaSigAlg;
    private final String tradSigAlg;
    /**
     * Per-algorithm label bytes (ASCII) used in M' construction per §2.2,
     * e.g. {@code "COMPSIG-MLDSA44-RSA2048-PSS-SHA256"}.
     * For most algorithms this is {@code "COMPSIG-" + compositeAlg}, but
     * brainpool algorithms use abbreviated labels per §6
     * (e.g. {@code "COMPSIG-MLDSA65-ECDSA-BP256-SHA512"}).
     */
    private final byte[] label;
    /**
     * JCA name or sentinel for the pre-hash function PH per draft §6.
     * Standard values: {@code "SHA-256"}, {@code "SHA-512"}.
     * Special sentinel: {@code "SHAKE256-64"} indicates SHAKE256 with 64-byte
     * output, used for {@code MLDSA87-Ed448-SHAKE256}.  This sentinel triggers
     * the OCK Digest path in {@link #buildDomainSeparatedMessage} because
     * SHAKE256 is not registered as a JCA {@code MessageDigest} in OpenJCEPlus.
     */
    private final String phAlg;

    /** Buffered message bytes accumulated via {@code engineUpdate}. */
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();

    private Signature mldsaSig;
    private Signature tradSig;
    private final PSSParameterSpec tradPssParams;
    private boolean initSign = false;
    private boolean initVerify = false;

    /**
     * @param provider     the OpenJCEPlus provider instance
     * @param compositeAlg the composite algorithm standard name
     * @param mldsaSigAlg  the JCA algorithm name for the ML-DSA Signature engine
     *                     (e.g. {@code "ML-DSA-44"})
     * @param tradSigAlg   the JCA algorithm name for the traditional Signature engine
     *                     (e.g. {@code "SHA256withECDSA"})
     * @param phAlg        the JCA name of the pre-hash function PH per draft §6
     *                     (either {@code "SHA-256"} or {@code "SHA-512"})
     */
    /** Convenience constructor for non-RSA, non-PSS algorithms. */
    CompositeSignatureImpl(OpenJCEPlusProvider provider,
            String compositeAlg, String mldsaSigAlg, String tradSigAlg, String phAlg) {
        this(provider, compositeAlg, mldsaSigAlg, tradSigAlg, phAlg, null, 0);
    }

    /**
     * Extended constructor for algorithms with a label override (e.g. brainpool).
     *
     * @param labelOverride the ASCII label string to use in M' construction,
     *                      or {@code null} to derive it as
     *                      {@code "COMPSIG-" + compositeAlg}
     */
    CompositeSignatureImpl(OpenJCEPlusProvider provider,
            String compositeAlg, String mldsaSigAlg, String tradSigAlg, String phAlg,
            String labelOverride) {
        this(provider, compositeAlg, mldsaSigAlg, tradSigAlg, phAlg, labelOverride, 0);
    }

    /**
     * Extended constructor for RSA-PSS algorithms that need an explicit key size
     * to select the correct PSS hash per draft §6.1 Tables 2 and 3.
     *
     * @param rsaKeyBits RSA modulus size in bits (e.g. 2048, 3072, 4096)
     */
    CompositeSignatureImpl(OpenJCEPlusProvider provider,
            String compositeAlg, String mldsaSigAlg, String tradSigAlg, String phAlg,
            int rsaKeyBits) {
        this(provider, compositeAlg, mldsaSigAlg, tradSigAlg, phAlg, null, rsaKeyBits);
    }

    /**
     * Full constructor.
     *
     * @param labelOverride the ASCII label override, or {@code null} for default
     * @param rsaKeyBits    RSA key size in bits used to select the PSS hash per
     *                      draft §6.1 Tables 2 and 3; {@code 0} for non-PSS
     *                      algorithms (value is ignored)
     */
    CompositeSignatureImpl(OpenJCEPlusProvider provider,
            String compositeAlg, String mldsaSigAlg, String tradSigAlg, String phAlg,
            String labelOverride, int rsaKeyBits) {
        this.provider = provider;
        this.compositeAlg = compositeAlg;
        this.mldsaSigAlg = mldsaSigAlg;
        this.tradSigAlg = tradSigAlg;
        this.label = (labelOverride != null ? labelOverride : "COMPSIG-" + compositeAlg)
                .getBytes(StandardCharsets.US_ASCII);
        this.phAlg = phAlg;
        this.tradPssParams = buildPssParams(tradSigAlg, rsaKeyBits);
        if (null != tradPssParams) {
            tradSigAlg = "RSAPSS";
        }

        try {
            this.mldsaSig = Signature.getInstance(mldsaSigAlg, provider);
            this.tradSig = Signature.getInstance(tradSigAlg, provider);
        } catch (Exception e) {
            throw provider.providerException(
                    "Failed to initialize composite signature engines", e);
        }
    }

    /**
     * Builds the {@link PSSParameterSpec} required by the traditional RSA-PSS
     * component per draft §6.1 Tables 2 and 3:
     * <ul>
     *   <li>2048-bit and 3072-bit keys → SHA-256, MGF1(SHA-256), saltLen=32</li>
     *   <li>4096-bit keys              → SHA-384, MGF1(SHA-384), saltLen=48</li>
     * </ul>
     * Returns {@code null} for non-PSS algorithms.
     *
     * @param tradSigAlg the traditional signature algorithm name
     * @param rsaKeyBits RSA modulus size in bits (2048, 3072, or 4096)
     */
    private static PSSParameterSpec buildPssParams(String tradSigAlg, int rsaKeyBits) {
        String up = tradSigAlg.toUpperCase(java.util.Locale.ROOT);
        if (!up.contains("PSS")) {
            return null;
        }
        // Select hash and salt length from the RSA key size per draft §6.1 Tables 2 & 3.
        // 4096-bit keys use SHA-384; all others (2048, 3072) use SHA-256.
        String hashName = (rsaKeyBits >= 4096) ? "SHA-384" : "SHA-256";
        int saltLen = (rsaKeyBits >= 4096) ? 48 : 32;
        return new PSSParameterSpec(
                hashName,                        // mdName
                "MGF1",                          // mgfName
                new MGF1ParameterSpec(hashName),  // MGFParameterSpec
                saltLen,                         // saltLen
                PSSParameterSpec.TRAILER_FIELD_BC); // trailerField = 1
    }

    // -----------------------------------------------------------------------
    // SignatureSpi implementation
    // -----------------------------------------------------------------------

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof CompositePrivateKey)) {
            throw new InvalidKeyException(
                    "Expected CompositePrivateKey, got: "
                            + privateKey.getClass().getName());
        }
        CompositePrivateKey ck = (CompositePrivateKey) privateKey;
        if (!compositeAlg.equalsIgnoreCase(ck.getAlgorithm())) {
            throw new InvalidKeyException(
                    "Key algorithm " + ck.getAlgorithm()
                            + " does not match signature algorithm " + compositeAlg);
        }
        try {
            PrivateKey mldsaKey = decodeMLDSAPrivateKey(ck.getMLDSASeed());
            PrivateKey tradKey = decodeTradPrivateKey(tradSigAlg, ck.getTradRaw());
            mldsaSig.initSign(mldsaKey);
            tradSig.initSign(tradKey);
            if (tradPssParams != null) {
                tradSig.setParameter(tradPssParams);
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize sign operation", e);
        }
        initSign = true;
        initVerify = false;
        message.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof CompositePublicKey)) {
            throw new InvalidKeyException(
                    "Expected CompositePublicKey, got: "
                            + publicKey.getClass().getName());
        }
        CompositePublicKey ck = (CompositePublicKey) publicKey;
        if (!compositeAlg.equalsIgnoreCase(ck.getAlgorithm())) {
            throw new InvalidKeyException(
                    "Key algorithm " + ck.getAlgorithm()
                            + " does not match signature algorithm " + compositeAlg);
        }
        try {
            PublicKey mldsaKey = decodeMLDSAPublicKey(ck.getMLDSARaw());
            PublicKey tradKey = decodeTradPublicKey(tradSigAlg, ck.getTradRaw());
            mldsaSig.initVerify(mldsaKey);
            tradSig.initVerify(tradKey);
            if (tradPssParams != null) {
                tradSig.setParameter(tradPssParams);
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize verify operation", e);
        }
        initSign = false;
        initVerify = true;
        message.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        message.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        message.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!initSign) {
            throw new SignatureException("Signature not initialized for signing");
        }
        try {
            byte[] domainMsg = buildDomainSeparatedMessage(message.toByteArray());
            message.reset();

            // WI-5 (NOT YET IMPLEMENTED): Draft §3.2 step 4 requires:
            //   mldsaSig = ML-DSA.Sign(mldsaSK, M', mldsa_ctx=Label)
            // i.e. the per-algorithm Label must be passed as the internal ML-DSA
            // context string.  The underlying PQCSignature / OCK native interface
            // currently exposes PQC_SIGNATURE_sign(pkeyId, data) with no ctx
            // parameter.  A new JNI method
            //   PQC_SIGNATURE_sign_with_ctx(pkeyId, data, ctx)
            // must be added to NativeOCKImplementation and NativeInterface before
            // this step can be implemented.  Until then, ML-DSA signs M' with an
            // empty context (mldsa_ctx=""), which diverges from the draft.
            mldsaSig.update(domainMsg);
            tradSig.update(domainMsg);

            byte[] mldsaSigBytes = mldsaSig.sign();
            byte[] tradSigBytes = tradSig.sign();

            return encodeCompositeSignature(mldsaSigBytes, tradSigBytes);
        } catch (Exception e) {
            throw new SignatureException("Composite sign failed", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!initVerify) {
            throw new SignatureException("Signature not initialized for verification");
        }
        if (sigBytes == null) {
            return false;
        }
        try {
            byte[][] components = decodeCompositeSignature(sigBytes);
            byte[] mldsaSigBytes = components[0];
            byte[] tradSigBytes = components[1];

            byte[] domainMsg = buildDomainSeparatedMessage(message.toByteArray());
            message.reset();

            // WI-5 (NOT YET IMPLEMENTED): same native gap as in engineSign() —
            // ML-DSA verification must use mldsa_ctx=Label.
            mldsaSig.update(domainMsg);
            tradSig.update(domainMsg);

            boolean mldsaOk = mldsaSig.verify(mldsaSigBytes);
            boolean tradOk = tradSig.verify(tradSigBytes);
            return mldsaOk && tradOk;
        } catch (Exception e) {
            return false;
        }
    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "No parameters accepted for composite algorithm " + compositeAlg);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    // -----------------------------------------------------------------------
    // Message representative construction (draft §2.2)
    // -----------------------------------------------------------------------

    /**
     * Builds the message representative M' per draft §2.2:
     * <pre>
     * M' = Prefix || Label || len(ctx) || ctx || PH( M )
     * </pre>
     * {@code ctx} is treated as empty (len = 0) since this API does not
     * expose a context parameter.  {@code PH} is the per-algorithm pre-hash
     * function stored in {@link #phAlg}.
     *
     * <p>When {@link #phAlg} is the sentinel {@code "SHAKE256-64"} (used by
     * {@code MLDSA87-Ed448-SHAKE256}), the OCK {@link Digest} facility is
     * used directly to compute 64 bytes of SHAKE256 output, because SHAKE256
     * is not registered as a JCA {@code MessageDigest} service in OpenJCEPlus.
     */
    private byte[] buildDomainSeparatedMessage(byte[] msg) throws SignatureException {
        try {
            final byte[] ph;
            if ("SHAKE256-64".equals(phAlg)) {
                // SHAKE256 is not available via MessageDigest.getInstance() in
                // OpenJCEPlus (the provider registration is commented out).
                // Use the OCK Digest layer directly with the OCK algorithm name
                // "SHAKE256" and truncate the output to 64 bytes as specified
                // by draft §6 for MLDSA87-Ed448-SHAKE256.
                Digest shake = Digest.getInstance("SHAKE256", provider, "SHAKE256-64");
                shake.update(msg, 0, msg.length);
                byte[] raw = shake.digest();
                // SHAKE256 is an XOF; OCK may return its internal block size.
                // The draft specifies exactly 64 bytes of output.
                ph = (raw.length >= 64) ? Arrays.copyOf(raw, 64) : raw;
            } else {
                java.security.MessageDigest md =
                        java.security.MessageDigest.getInstance(phAlg);
                ph = md.digest(msg);
            }

            ByteArrayOutputStream buf = new ByteArrayOutputStream(
                    DOMAIN_PREFIX.length + label.length + 1 + ph.length);
            buf.write(DOMAIN_PREFIX, 0, DOMAIN_PREFIX.length); // Prefix
            buf.write(label, 0, label.length);                  // Label ("COMPSIG-...")
            buf.write(0x00);                                    // len(ctx) = 0
            // ctx is empty -- nothing to write
            buf.write(ph, 0, ph.length);                        // PH( M )
            return buf.toByteArray();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new SignatureException(
                    "Pre-hash algorithm not available: " + phAlg, e);
        } catch (Exception e) {
            throw new SignatureException(
                    "Pre-hash computation failed for: " + phAlg, e);
        }
    }

    // -----------------------------------------------------------------------
    // Composite signature encoding / decoding (draft §4.3)
    // -----------------------------------------------------------------------

    /**
     * Serializes two component signature values as raw concatenation per §4.3:
     * <pre>
     * CompositeSignatureValue = mldsaSig || tradSig
     * </pre>
     */
    private static byte[] encodeCompositeSignature(byte[] mldsaSig, byte[] tradSig) {
        byte[] out = new byte[mldsaSig.length + tradSig.length];
        System.arraycopy(mldsaSig, 0, out, 0, mldsaSig.length);
        System.arraycopy(tradSig,  0, out, mldsaSig.length, tradSig.length);
        return out;
    }

    /**
     * Deserializes a composite signature value by splitting at the fixed
     * ML-DSA signature length per §4.3.
     *
     * @return two-element array {@code {mldsaSigBytes, tradSigBytes}}
     * @throws SignatureException if the encoding is too short
     */
    private byte[][] decodeCompositeSignature(byte[] encoded)
            throws SignatureException {
        int mldsaLen = CompositeSignatureUtils.mldsaSignatureLen(compositeAlg);
        if (encoded.length < mldsaLen) {
            throw new SignatureException(
                    "Composite signature too short: " + encoded.length
                            + " < " + mldsaLen);
        }
        byte[] mldsa = Arrays.copyOfRange(encoded, 0, mldsaLen);
        byte[] trad  = Arrays.copyOfRange(encoded, mldsaLen, encoded.length);
        return new byte[][] {mldsa, trad};
    }

    // -----------------------------------------------------------------------
    // Key helpers
    // -----------------------------------------------------------------------

    /**
     * Reconstructs an ML-DSA PrivateKey from the raw 32-byte seed by wrapping
     * it in a minimal PKCS#8 structure that the ML-DSA KeyFactory can parse.
     */
    private PrivateKey decodeMLDSAPrivateKey(byte[] mldsaSeed) throws Exception {
        java.security.KeyFactory kf =
                java.security.KeyFactory.getInstance(mldsaSigAlg, provider);
        return kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(
                        wrapSeedAsPkcs8(mldsaSeed)));
    }

    /**
     * Reconstructs a traditional PrivateKey from its raw bytes.
     * The raw bytes are wrapped in the appropriate PKCS#8 / DER structure
     * before being handed to the component KeyFactory.
     */
    private PrivateKey decodeTradPrivateKey(String sigAlg, byte[] rawBytes)
            throws Exception {
        String kfAlg = keyFactoryAlg(sigAlg);
        java.security.KeyFactory kf =
                java.security.KeyFactory.getInstance(kfAlg, provider);
        return kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(rawBytes));
    }

    /**
     * Reconstructs an ML-DSA PublicKey from the raw public key bytes by
     * wrapping them in a minimal SubjectPublicKeyInfo structure.
     */
    private PublicKey decodeMLDSAPublicKey(byte[] mldsaRaw) throws Exception {
        java.security.KeyFactory kf =
                java.security.KeyFactory.getInstance(mldsaSigAlg, provider);
        return kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(
                        wrapRawAsSpki(mldsaSigAlg, mldsaRaw)));
    }

    /**
     * Reconstructs a traditional PublicKey from the raw public key bytes by
     * wrapping them in a minimal SubjectPublicKeyInfo structure.
     */
    private PublicKey decodeTradPublicKey(String sigAlg, byte[] rawBytes)
            throws Exception {
        String kfAlg = keyFactoryAlg(sigAlg);
        java.security.KeyFactory kf =
                java.security.KeyFactory.getInstance(kfAlg, provider);
        return kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(rawBytes));
    }

    /**
     * Wraps a raw ML-DSA seed in a minimal OneAsymmetricKey (PKCS#8) structure
     * so the ML-DSA KeyFactory can parse it.
     */
    private byte[] wrapSeedAsPkcs8(byte[] seed) throws java.io.IOException {
        sun.security.util.DerOutputStream algId = new sun.security.util.DerOutputStream();
        algId.putOID(
                sun.security.util.ObjectIdentifier.of(
                        com.ibm.crypto.plus.provider.PQCKnownOIDs
                                .findMatch(mldsaSigAlg).value()));

        sun.security.util.DerOutputStream pkcs8 = new sun.security.util.DerOutputStream();
        pkcs8.putInteger(0);
        pkcs8.write(sun.security.util.DerValue.tag_Sequence, algId);
        pkcs8.putOctetString(seed);

        sun.security.util.DerOutputStream out = new sun.security.util.DerOutputStream();
        out.write(sun.security.util.DerValue.tag_Sequence, pkcs8);
        return out.toByteArray();
    }

    /**
     * Wraps raw public key bytes in a minimal SubjectPublicKeyInfo so the
     * ML-DSA KeyFactory can parse them.
     */
    private byte[] wrapRawAsSpki(String algName, byte[] raw) throws java.io.IOException {
        sun.security.util.DerOutputStream algId = new sun.security.util.DerOutputStream();
        algId.putOID(
                sun.security.util.ObjectIdentifier.of(
                        com.ibm.crypto.plus.provider.PQCKnownOIDs
                                .findMatch(algName).value()));

        sun.security.util.DerOutputStream spki = new sun.security.util.DerOutputStream();
        spki.write(sun.security.util.DerValue.tag_Sequence, algId);
        spki.putBitString(raw);

        sun.security.util.DerOutputStream out = new sun.security.util.DerOutputStream();
        out.write(sun.security.util.DerValue.tag_Sequence, spki);
        return out.toByteArray();
    }

    /**
     * Maps a Signature algorithm name to the corresponding KeyFactory algorithm
     * name.  For example {@code "SHA256withECDSA"} → {@code "EC"}.
     */
    private static String keyFactoryAlg(String sigAlg) {
        String up = sigAlg.toUpperCase(java.util.Locale.ROOT);
        if (up.contains("ECDSA") || up.startsWith("EC")) {
            return "EC";
        }
        if (up.contains("RSA")) {
            return "RSA";
        }
        if (up.startsWith("ED25519") || up.equals("ED25519")) {
            return "Ed25519";
        }
        if (up.startsWith("ED448") || up.equals("ED448")) {
            return "Ed448";
        }
        // For ML-DSA component: sigAlg IS the key alg (e.g. "ML-DSA-44")
        return sigAlg;
    }

    // -----------------------------------------------------------------------
    // Concrete inner classes — one per composite algorithm combination
    // -----------------------------------------------------------------------

    // WI-7: PSS algorithms pass rsaKeyBits so buildPssParams() can select the
    // correct hash and salt length per draft §6.1 Tables 2 and 3.
    // WI-9: PKCS1 algorithms use the correct inner hash per draft §6.
    // WI-8: MLDSA65-ECDSA-P256-SHA512 uses SHA256withECDSA (not SHA512).
    // WI-4: MLDSA87-Ed448-SHAKE256 passes "SHAKE256-64" sentinel for PH.

    public static final class MLDSA44RSA2048PSSSHA256 extends CompositeSignatureImpl {
        public MLDSA44RSA2048PSSSHA256(OpenJCEPlusProvider p) {
            // 2048-bit → SHA-256/salt32 per Table 2
            super(p, "MLDSA44-RSA2048-PSS-SHA256", "ML-DSA-44",
                    "SHA256withRSASSA-PSS", "SHA-256", 2048);
        }
    }

    public static final class MLDSA44RSA2048PKCS15SHA256 extends CompositeSignatureImpl {
        public MLDSA44RSA2048PKCS15SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PKCS15-SHA256", "ML-DSA-44", "SHA256withRSA", "SHA-256");
        }
    }

    public static final class MLDSA44Ed25519SHA512 extends CompositeSignatureImpl {
        public MLDSA44Ed25519SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-Ed25519-SHA512", "ML-DSA-44", "Ed25519", "SHA-512");
        }
    }

    public static final class MLDSA44ECDSAP256SHA256 extends CompositeSignatureImpl {
        public MLDSA44ECDSAP256SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-ECDSA-P256-SHA256", "ML-DSA-44", "SHA256withECDSA", "SHA-256");
        }
    }

    public static final class MLDSA65RSA3072PSSSHA512 extends CompositeSignatureImpl {
        public MLDSA65RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            // 3072-bit → SHA-256/salt32 per Table 2 (WI-7)
            super(p, "MLDSA65-RSA3072-PSS-SHA512", "ML-DSA-65",
                    "SHA256withRSASSA-PSS", "SHA-512", 3072);
        }
    }

    public static final class MLDSA65RSA3072PKCS15SHA512 extends CompositeSignatureImpl {
        public MLDSA65RSA3072PKCS15SHA512(OpenJCEPlusProvider p) {
            // 3072-bit PKCS1 uses SHA-256 inner hash per draft §6 (WI-9)
            super(p, "MLDSA65-RSA3072-PKCS15-SHA512", "ML-DSA-65", "SHA256withRSA", "SHA-512");
        }
    }

    public static final class MLDSA65RSA4096PSSSHA512 extends CompositeSignatureImpl {
        public MLDSA65RSA4096PSSSHA512(OpenJCEPlusProvider p) {
            // 4096-bit → SHA-384/salt48 per Table 3 (WI-7)
            super(p, "MLDSA65-RSA4096-PSS-SHA512", "ML-DSA-65",
                    "SHA384withRSASSA-PSS", "SHA-512", 4096);
        }
    }

    public static final class MLDSA65RSA4096PKCS15SHA512 extends CompositeSignatureImpl {
        public MLDSA65RSA4096PKCS15SHA512(OpenJCEPlusProvider p) {
            // 4096-bit PKCS1 uses SHA-384 inner hash per draft §6 (WI-9)
            super(p, "MLDSA65-RSA4096-PKCS15-SHA512", "ML-DSA-65", "SHA384withRSA", "SHA-512");
        }
    }

    public static final class MLDSA65ECDSAP256SHA512 extends CompositeSignatureImpl {
        public MLDSA65ECDSAP256SHA512(OpenJCEPlusProvider p) {
            // P-256 uses SHA256withECDSA, not SHA512withECDSA (WI-8)
            super(p, "MLDSA65-ECDSA-P256-SHA512", "ML-DSA-65", "SHA256withECDSA", "SHA-512");
        }
    }

    public static final class MLDSA65ECDSAP384SHA512 extends CompositeSignatureImpl {
        public MLDSA65ECDSAP384SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-P384-SHA512", "ML-DSA-65", "SHA384withECDSA", "SHA-512");
        }
    }

    public static final class MLDSA65ECDSABrainpoolP256r1SHA512 extends CompositeSignatureImpl {
        public MLDSA65ECDSABrainpoolP256r1SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-brainpoolP256r1-SHA512", "ML-DSA-65",
                    "SHA256withECDSA", "SHA-512",
                    "COMPSIG-MLDSA65-ECDSA-BP256-SHA512");
        }
    }

    public static final class MLDSA65Ed25519SHA512 extends CompositeSignatureImpl {
        public MLDSA65Ed25519SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-Ed25519-SHA512", "ML-DSA-65", "Ed25519", "SHA-512");
        }
    }

    public static final class MLDSA87ECDSAP384SHA512 extends CompositeSignatureImpl {
        public MLDSA87ECDSAP384SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P384-SHA512", "ML-DSA-87", "SHA384withECDSA", "SHA-512");
        }
    }

    public static final class MLDSA87ECDSABrainpoolP384r1SHA512 extends CompositeSignatureImpl {
        public MLDSA87ECDSABrainpoolP384r1SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-brainpoolP384r1-SHA512", "ML-DSA-87",
                    "SHA384withECDSA", "SHA-512",
                    "COMPSIG-MLDSA87-ECDSA-BP384-SHA512");
        }
    }

    public static final class MLDSA87Ed448SHAKE256 extends CompositeSignatureImpl {
        public MLDSA87Ed448SHAKE256(OpenJCEPlusProvider p) {
            // PH = SHAKE256(M, 64) — use sentinel "SHAKE256-64" (WI-4)
            super(p, "MLDSA87-Ed448-SHAKE256", "ML-DSA-87", "Ed448", "SHAKE256-64");
        }
    }

    public static final class MLDSA87RSA3072PSSSHA512 extends CompositeSignatureImpl {
        public MLDSA87RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            // 3072-bit → SHA-256/salt32 per Table 2 (WI-7)
            super(p, "MLDSA87-RSA3072-PSS-SHA512", "ML-DSA-87",
                    "SHA256withRSASSA-PSS", "SHA-512", 3072);
        }
    }

    public static final class MLDSA87RSA4096PSSSHA512 extends CompositeSignatureImpl {
        public MLDSA87RSA4096PSSSHA512(OpenJCEPlusProvider p) {
            // 4096-bit → SHA-384/salt48 per Table 3 (WI-7)
            super(p, "MLDSA87-RSA4096-PSS-SHA512", "ML-DSA-87",
                    "SHA384withRSASSA-PSS", "SHA-512", 4096);
        }
    }

    public static final class MLDSA87ECDSAP521SHA512 extends CompositeSignatureImpl {
        public MLDSA87ECDSAP521SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P521-SHA512", "ML-DSA-87", "SHA512withECDSA", "SHA-512");
        }
    }
}
