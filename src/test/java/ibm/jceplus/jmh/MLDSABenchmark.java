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
public class MLDSABenchmark extends JMHBase {

    @Param({"64", "1024", "8192", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    private KeyPairGenerator mldsa44KeyPairGenerator;
    private KeyPairGenerator mldsa65KeyPairGenerator;
    private KeyPairGenerator mldsa87KeyPairGenerator;
    private Signature mldsa44SignatureInstance;
    private Signature mldsa65SignatureInstance;
    private Signature mldsa87SignatureInstance;
    private Signature mldsa44VerifierInstance;
    private Signature mldsa65VerifierInstance;
    private Signature mldsa87VerifierInstance;
    private KeyPair mldsa44keyPair;
    private KeyPair mldsa65keyPair;
    private KeyPair mldsa87keyPair;
    private byte[] mldsa44signature;
    private byte[] mldsa65signature;
    private byte[] mldsa87signature;
    private byte[] payload;
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        mldsa44KeyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-44", provider);
        mldsa65KeyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-65", provider);
        mldsa87KeyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-87", provider);

        mldsa44SignatureInstance = Signature.getInstance("ML-DSA-44", provider);
        mldsa65SignatureInstance = Signature.getInstance("ML-DSA-65", provider);
        mldsa87SignatureInstance = Signature.getInstance("ML-DSA-87", provider);

        mldsa44VerifierInstance = Signature.getInstance("ML-DSA-44", provider);
        mldsa65VerifierInstance = Signature.getInstance("ML-DSA-65", provider);
        mldsa87VerifierInstance = Signature.getInstance("ML-DSA-87", provider);

        mldsa44keyPair = mldsa44KeyPairGenerator.generateKeyPair();
        mldsa65keyPair = mldsa65KeyPairGenerator.generateKeyPair();
        mldsa87keyPair = mldsa87KeyPairGenerator.generateKeyPair();

        mldsa44SignatureInstance.initSign(mldsa44keyPair.getPrivate());
        mldsa65SignatureInstance.initSign(mldsa65keyPair.getPrivate());
        mldsa87SignatureInstance.initSign(mldsa87keyPair.getPrivate());

        payload = new byte[payloadSize];
        random.nextBytes(payload);

        mldsa44SignatureInstance.update(payload);
        mldsa65SignatureInstance.update(payload);
        mldsa87SignatureInstance.update(payload);

        mldsa44signature = mldsa44SignatureInstance.sign();
        mldsa65signature = mldsa65SignatureInstance.sign();
        mldsa87signature = mldsa87SignatureInstance.sign();
    }

    @Benchmark
    public KeyPair mldsa44KeyGeneration() throws Exception {
        return mldsa44KeyPairGenerator.generateKeyPair();
    }

    @Benchmark
    public KeyPair mldsa65KeyGeneration() throws Exception {
        return mldsa65KeyPairGenerator.generateKeyPair();
    }

    @Benchmark
    public KeyPair mldsa87KeyGeneration() throws Exception {
        return mldsa87KeyPairGenerator.generateKeyPair();
    }

    @Benchmark
    public byte[] mldsa44Sign() throws Exception {
        mldsa44SignatureInstance.initSign(mldsa44keyPair.getPrivate());
        mldsa44SignatureInstance.update(payload);
        return mldsa44SignatureInstance.sign();
    }

    @Benchmark
    public byte[] mldsa65Sign() throws Exception {
        mldsa65SignatureInstance.initSign(mldsa65keyPair.getPrivate());
        mldsa65SignatureInstance.update(payload);
        return mldsa65SignatureInstance.sign();
    }

    @Benchmark
    public byte[] mldsa87Sign() throws Exception {
        mldsa87SignatureInstance.initSign(mldsa87keyPair.getPrivate());
        mldsa87SignatureInstance.update(payload);
        return mldsa87SignatureInstance.sign();
    }

    @Benchmark
    public boolean mldsa44Verify() throws Exception {
        mldsa44VerifierInstance.initVerify(mldsa44keyPair.getPublic());
        mldsa44VerifierInstance.update(payload);
        return mldsa44VerifierInstance.verify(mldsa44signature);
    }

    @Benchmark
    public boolean mldsa65Verify() throws Exception {
        mldsa65VerifierInstance.initVerify(mldsa65keyPair.getPublic());
        mldsa65VerifierInstance.update(payload);
        return mldsa65VerifierInstance.verify(mldsa65signature);
    }

    @Benchmark
    public boolean mldsa87Verify() throws Exception {
        mldsa87VerifierInstance.initVerify(mldsa87keyPair.getPublic());
        mldsa87VerifierInstance.update(payload);
        return mldsa87VerifierInstance.verify(mldsa87signature);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MLDSABenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
