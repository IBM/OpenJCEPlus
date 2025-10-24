/*
 * Copyright IBM Corp. 2025
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

    @Param({"OpenJCEPlus", "SunEC"})
    private String provider;

    /**
     * EC curve sizes used for key generation.
     */
    @Param({"256", "521"})
    private int keySize;

    private KeyPairGenerator ecKeyPairGenerator;
    private Signature ecSha1SignatureInstance;
    private Signature ecSha224SignatureInstance;
    private Signature ecSha256SignatureInstance;
    private Signature ecSha512SignatureInstance;
    private Signature ecSha3_224SignatureInstance;
    private Signature ecSha3_256SignatureInstance;
    private Signature ecSha3_384SignatureInstance;
    private Signature ecSha3_512SignatureInstance;

    private Signature ecSha1VerifierInstance;
    private Signature ecSha224VerifierInstance;
    private Signature ecSha256VerifierInstance;
    private Signature ecSha512VerifierInstance;
    private Signature ecSha3_224VerifierInstance;
    private Signature ecSha3_256VerifierInstance;
    private Signature ecSha3_384VerifierInstance;
    private Signature ecSha3_512VerifierInstance;

    private KeyPair ecKeyPair;
    private byte[] ecSha1Signature;
    private byte[] ecSha224Signature;
    private byte[] ecSha256Signature;
    private byte[] ecSha512Signature;
    private byte[] ecSha3_224Signature;
    private byte[] ecSha3_256Signature;
    private byte[] ecSha3_384Signature;
    private byte[] ecSha3_512Signature;
    private byte[] payload;
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        ecKeyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
        ecKeyPairGenerator.initialize(keySize);

        ecSha1SignatureInstance = Signature.getInstance("SHA1withECDSA", provider);
        ecSha224SignatureInstance = Signature.getInstance("SHA224withECDSA", provider);
        ecSha256SignatureInstance = Signature.getInstance("SHA256withECDSA", provider);
        ecSha512SignatureInstance = Signature.getInstance("SHA512withECDSA", provider);
        ecSha3_224SignatureInstance = Signature.getInstance("SHA3-224withECDSA", provider);
        ecSha3_256SignatureInstance = Signature.getInstance("SHA3-256withECDSA", provider);
        ecSha3_384SignatureInstance = Signature.getInstance("SHA3-384withECDSA", provider);
        ecSha3_512SignatureInstance = Signature.getInstance("SHA3-512withECDSA", provider);

        ecSha1VerifierInstance = Signature.getInstance("SHA1withECDSA", provider);
        ecSha224VerifierInstance = Signature.getInstance("SHA224withECDSA", provider);
        ecSha256VerifierInstance = Signature.getInstance("SHA256withECDSA", provider);
        ecSha512VerifierInstance = Signature.getInstance("SHA512withECDSA", provider);
        ecSha3_224VerifierInstance = Signature.getInstance("SHA3-224withECDSA", provider);
        ecSha3_256VerifierInstance = Signature.getInstance("SHA3-256withECDSA", provider);
        ecSha3_384VerifierInstance = Signature.getInstance("SHA3-384withECDSA", provider);
        ecSha3_512VerifierInstance = Signature.getInstance("SHA3-512withECDSA", provider);

        ecKeyPair = ecKeyPairGenerator.generateKeyPair();

        ecSha1SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha224SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha256SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha512SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_224SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_256SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_384SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_512SignatureInstance.initSign(ecKeyPair.getPrivate());

        payload = new byte[payloadSize];
        random.nextBytes(payload);

        ecSha1SignatureInstance.update(payload);
        ecSha224SignatureInstance.update(payload);
        ecSha256SignatureInstance.update(payload);
        ecSha512SignatureInstance.update(payload);
        ecSha3_224SignatureInstance.update(payload);
        ecSha3_256SignatureInstance.update(payload);
        ecSha3_384SignatureInstance.update(payload);
        ecSha3_512SignatureInstance.update(payload);

        ecSha1Signature = ecSha1SignatureInstance.sign();
        ecSha224Signature = ecSha224SignatureInstance.sign();
        ecSha256Signature = ecSha256SignatureInstance.sign();
        ecSha512Signature = ecSha512SignatureInstance.sign();
        ecSha3_224Signature = ecSha3_224SignatureInstance.sign();
        ecSha3_256Signature = ecSha3_256SignatureInstance.sign();
        ecSha3_384Signature = ecSha3_384SignatureInstance.sign();
        ecSha3_512Signature= ecSha3_512SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha1Sign() throws Exception {
        ecSha1SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha1SignatureInstance.update(payload);
        return ecSha1SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha224Sign() throws Exception {
        ecSha224SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha224SignatureInstance.update(payload);
        return ecSha224SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha256Sign() throws Exception {
        ecSha256SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha256SignatureInstance.update(payload);
        return ecSha256SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha512Sign() throws Exception {
        ecSha512SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha512SignatureInstance.update(payload);
        return ecSha512SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha3_224Sign() throws Exception {
        ecSha3_224SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_224SignatureInstance.update(payload);
        return ecSha3_224SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha3_256Sign() throws Exception {
        ecSha3_256SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_256SignatureInstance.update(payload);
        return ecSha3_256SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha3_384Sign() throws Exception {
        ecSha3_384SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_384SignatureInstance.update(payload);
        return ecSha3_384SignatureInstance.sign();
    }

    @Benchmark
    public byte[] ecSha3_512Sign() throws Exception {
        ecSha3_512SignatureInstance.initSign(ecKeyPair.getPrivate());
        ecSha3_512SignatureInstance.update(payload);
        return ecSha3_512SignatureInstance.sign();
    }

    @Benchmark
    public boolean ecSha1Verify() throws Exception {
        ecSha1VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha1VerifierInstance.update(payload);
        return ecSha1VerifierInstance.verify(ecSha1Signature);
    }

    @Benchmark
    public boolean ecSha224Verify() throws Exception {
        ecSha224VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha224VerifierInstance.update(payload);
        return ecSha224VerifierInstance.verify(ecSha224Signature);
    }

    @Benchmark
    public boolean ecSha256Verify() throws Exception {
        ecSha256VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha256VerifierInstance.update(payload);
        return ecSha256VerifierInstance.verify(ecSha256Signature);
    }

    @Benchmark
    public boolean ecSha512Verify() throws Exception {
        ecSha512VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha512VerifierInstance.update(payload);
        return ecSha512VerifierInstance.verify(ecSha512Signature);
    }

    @Benchmark
    public boolean ecSha3_224Verify() throws Exception {
        ecSha3_224VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha3_224VerifierInstance.update(payload);
        return ecSha3_224VerifierInstance.verify(ecSha3_224Signature);
    }

    @Benchmark
    public boolean ecSha3_256Verify() throws Exception {
        ecSha3_256VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha3_256VerifierInstance.update(payload);
        return ecSha3_256VerifierInstance.verify(ecSha3_256Signature);
    }

    @Benchmark
    public boolean ecSha3_384Verify() throws Exception {
        ecSha3_384VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha3_384VerifierInstance.update(payload);
        return ecSha3_384VerifierInstance.verify(ecSha3_384Signature);
    }

    @Benchmark
    public boolean ecSha3_512Verify() throws Exception {
        ecSha3_512VerifierInstance.initVerify(ecKeyPair.getPublic());
        ecSha3_512VerifierInstance.update(payload);
        return ecSha3_512VerifierInstance.verify(ecSha3_512Signature);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = ECSignatureBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
