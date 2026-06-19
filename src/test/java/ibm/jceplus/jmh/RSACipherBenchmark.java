/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.spec.MGF1ParameterSpec;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
public class RSACipherBenchmark extends AsymmetricCipherBase {

    @Param({"2048"})
    private int keySize;

    @Param({"OpenJCEPlus", "OpenJCEPlusFIPS", "SunJCE"})
    private String provider;

    /**
     * RSA padding modes to benchmark.
     * Non-FIPS compliant paddings (NoPadding, PKCS1Padding, OAEPPadding with SHA-1) will be skipped when provider is OpenJCEPlusFIPS.
     */
    @Param({"NoPadding", "PKCS1Padding", "OAEPPadding", "OAEPWithSHA-256AndMGF1Padding",
            "OAEPWithSHA-512AndMGF1Padding", "OAEPWithSHA-512/224AndMGF1Padding"})
    private String padding;

    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private byte[] plaintext;
    private byte[] ciphertext;
    private OAEPParameterSpec oaepSpec;

    @Setup
    public void setup() throws Exception {
        super.setup(keySize, "RSA", provider);

        boolean isFIPS = provider.equalsIgnoreCase("OpenJCEPlusFIPS");
        
        // Skip non-FIPS compliant paddings when using OpenJCEPlusFIPS provider
        if (isFIPS && (padding.equals("NoPadding") || padding.equals("PKCS1Padding") || padding.equals("OAEPPadding"))) {
            throw new RunnerException("Skipping " + padding + " for FIPS provider (not FIPS compliant)");
        }

        // Determine hash algorithm and MGF1 spec for OAEP padding
        String hashAlg = null;
        String mgf1Alg = null;
        int paddingOverhead;
        switch (padding) {
            case "NoPadding":
                paddingOverhead = 1;
                break;
            case "PKCS1Padding":
                paddingOverhead = 11;
                break;
            case "OAEPPadding":
                // Default OAEP uses SHA-1, which is not FIPS compliant
                hashAlg = "SHA-1";
                mgf1Alg = "SHA-1";
                paddingOverhead = (2 * 20 + 2); // SHA-1 size is 20 bytes
                break;
            case "OAEPWithSHA-256AndMGF1Padding":
                hashAlg = "SHA-256";
                mgf1Alg = "SHA-256";
                paddingOverhead = (2 * 32 + 2); // SHA-256 size is 32 bytes
                break;
            case "OAEPWithSHA-512AndMGF1Padding":
                hashAlg = "SHA-512";
                mgf1Alg = "SHA-512";
                paddingOverhead = (2 * 64 + 2); // SHA-512 size is 64 bytes
                break;
            case "OAEPWithSHA-512/224AndMGF1Padding":
                hashAlg = "SHA-512/224";
                mgf1Alg = "SHA-512/224";
                paddingOverhead = (2 * 28 + 2); // SHA-512/224 size is 28 bytes
                break;
            default:
                throw new IllegalArgumentException("Unknown padding: " + padding);
        }

        // Create OAEPParameterSpec for OAEP paddings
        if (hashAlg != null) {
            oaepSpec = new OAEPParameterSpec(
                hashAlg,
                "MGF1",
                new MGF1ParameterSpec(mgf1Alg),
                PSource.PSpecified.DEFAULT
            );
        }

        encryptCipher = Cipher.getInstance("RSA/ECB/" + padding, provider);
        decryptCipher = Cipher.getInstance("RSA/ECB/" + padding, provider);

        int payloadSize = (keySize / 8) - paddingOverhead;
        plaintext = new byte[payloadSize];
        random.nextBytes(plaintext);

        // Initialize ciphers with appropriate parameters
        if (oaepSpec != null) {
            // For OAEP padding, use explicit parameters (required for FIPS)
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
        } else {
            // For non-OAEP padding, no parameters needed
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        }
        
        if (plaintext.length > 0) {
            ciphertext = encryptCipher.doFinal(plaintext);
        }

        if (oaepSpec != null) {
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec);
        } else {
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        }
    }

    @Benchmark
    public byte[] encrypt() throws Exception {
        return encryptCipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] decrypt() throws Exception {
        return decryptCipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RSACipherBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
