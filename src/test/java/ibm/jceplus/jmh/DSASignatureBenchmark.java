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
public class DSASignatureBenchmark extends JMHBase {

    @Param({"2048", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    @Param({"2048"})
    private int keySize;

    private KeyPairGenerator dsaKeyPairGenerator;
    private Signature dsaSha1SignatureInstance;
    private Signature dsaSha224SignatureInstance;
    private Signature dsaSha256SignatureInstance;
    private Signature dsaSha1VerifierInstance;
    private Signature dsaSha224VerifierInstance;
    private Signature dsaSha256VerifierInstance;
    private KeyPair dsaKeyPair;
    private byte[] dsaSha1signature;
    private byte[] dsaSha224signature;
    private byte[] dsaSha256signature;
    private byte[] payload;
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        dsaKeyPairGenerator = KeyPairGenerator.getInstance("DSA", provider);
        dsaKeyPairGenerator.initialize(keySize);

        dsaSha1SignatureInstance = Signature.getInstance("SHA1withDSA", provider);
        dsaSha224SignatureInstance = Signature.getInstance("SHA224withDSA", provider);
        dsaSha256SignatureInstance = Signature.getInstance("SHA256withDSA", provider);

        dsaSha1VerifierInstance = Signature.getInstance("SHA1withDSA", provider);
        dsaSha224VerifierInstance = Signature.getInstance("SHA224withDSA", provider);
        dsaSha256VerifierInstance = Signature.getInstance("SHA256withDSA", provider);

        dsaKeyPair = dsaKeyPairGenerator.generateKeyPair();

        dsaSha1SignatureInstance.initSign(dsaKeyPair.getPrivate());
        dsaSha224SignatureInstance.initSign(dsaKeyPair.getPrivate());
        dsaSha256SignatureInstance.initSign(dsaKeyPair.getPrivate());

        payload = new byte[payloadSize];
        random.nextBytes(payload);

        dsaSha1SignatureInstance.update(payload);
        dsaSha224SignatureInstance.update(payload);
        dsaSha256SignatureInstance.update(payload);

        dsaSha1signature = dsaSha1SignatureInstance.sign();
        dsaSha224signature = dsaSha224SignatureInstance.sign();
        dsaSha256signature = dsaSha256SignatureInstance.sign();
    }

    @Benchmark
    public byte[] dsaSha1Sign() throws Exception {
        dsaSha1SignatureInstance.initSign(dsaKeyPair.getPrivate());
        dsaSha1SignatureInstance.update(payload);
        return dsaSha1SignatureInstance.sign();
    }

    @Benchmark
    public byte[] dsaSha224Sign() throws Exception {
        dsaSha224SignatureInstance.initSign(dsaKeyPair.getPrivate());
        dsaSha224SignatureInstance.update(payload);
        return dsaSha224SignatureInstance.sign();
    }

    @Benchmark
    public byte[] dsaSha256Sign() throws Exception {
        dsaSha256SignatureInstance.initSign(dsaKeyPair.getPrivate());
        dsaSha256SignatureInstance.update(payload);
        return dsaSha256SignatureInstance.sign();
    }

    @Benchmark
    public boolean dsaSha1Verify() throws Exception {
        dsaSha1VerifierInstance.initVerify(dsaKeyPair.getPublic());
        dsaSha1VerifierInstance.update(payload);
        return dsaSha1VerifierInstance.verify(dsaSha1signature);
    }

    @Benchmark
    public boolean dsaSha224Verify() throws Exception {
        dsaSha224VerifierInstance.initVerify(dsaKeyPair.getPublic());
        dsaSha224VerifierInstance.update(payload);
        return dsaSha224VerifierInstance.verify(dsaSha224signature);
    }

    @Benchmark
    public boolean dsaSha256Verify() throws Exception {
        dsaSha256VerifierInstance.initVerify(dsaKeyPair.getPublic());
        dsaSha256VerifierInstance.update(payload);
        return dsaSha256VerifierInstance.verify(dsaSha256signature);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = DSASignatureBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
