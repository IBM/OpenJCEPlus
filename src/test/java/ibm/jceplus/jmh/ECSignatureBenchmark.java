/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.concurrent.TimeUnit;
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
public class ECSignatureBenchmark extends JMHBase {

    @Param({"2048", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "OpenJCEPlusFIPS", "SunEC"})
    private String provider;

    /**
     * EC curve sizes used for key generation.
     */
    @Param({"256", "521"})
    private int keySize;

    /**
     * Signature algorithms to benchmark.
     * Non-FIPS compliant algorithms (SHA1withECDSA, SHA224withECDSA, SHA3-224withECDSA)
     * will be skipped when provider is OpenJCEPlusFIPS.
     */
    @Param({"SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA512withECDSA",
            "SHA3-224withECDSA", "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA"})
    private String algorithm;

    private KeyPairGenerator ecKeyPairGenerator;
    private Signature signatureInstance;
    private Signature verifierInstance;
    private KeyPair ecKeyPair;
    private byte[] signature;
    private byte[] payload;
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        super.setup(provider);

        // Skip non-FIPS compliant algorithms when using OpenJCEPlusFIPS provider
        if (provider.equalsIgnoreCase("OpenJCEPlusFIPS") &&
            (algorithm.equals("SHA1withECDSA") || 
             algorithm.equals("SHA224withECDSA") ||
             algorithm.equals("SHA3-224withECDSA") ||
             algorithm.equals("SHA3-2564withECDSA") ||
             algorithm.equals("SHA3-384withECDSA") ||
             algorithm.equals("SHA3-512withECDSA"))) {
            throw new RunnerException("Skipping " + algorithm + " for FIPS provider");
        }

        ecKeyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
        ecKeyPairGenerator.initialize(keySize);

        signatureInstance = Signature.getInstance(algorithm, provider);
        verifierInstance = Signature.getInstance(algorithm, provider);

        ecKeyPair = ecKeyPairGenerator.generateKeyPair();

        signatureInstance.initSign(ecKeyPair.getPrivate());

        payload = new byte[payloadSize];
        random.nextBytes(payload);

        signatureInstance.update(payload);
        signature = signatureInstance.sign();
    }

    @Benchmark
    public byte[] sign() throws Exception {
        signatureInstance.initSign(ecKeyPair.getPrivate());
        signatureInstance.update(payload);
        return signatureInstance.sign();
    }

    @Benchmark
    public boolean verify() throws Exception {
        verifierInstance.initVerify(ecKeyPair.getPublic());
        verifierInstance.update(payload);
        return verifierInstance.verify(signature);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = ECSignatureBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
