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
public class RSASignatureBenchmark extends JMHBase {

    @Param({"2048", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SunRsaSign"})
    private String provider;

    @Param({"2048", "4096"})
    private int keySize;

    private KeyPairGenerator rsaKeyPairGenerator;
    private Signature rsaSha256SignatureInstance;
    private Signature rsaSha384SignatureInstance;
    private Signature rsaSha512SignatureInstance;
    private Signature rsaSha256VerifierInstance;
    private Signature rsaSha384VerifierInstance;
    private Signature rsaSha512VerifierInstance;
    private KeyPair rsaKeyPair;
    private byte[] rsaSha256signature;
    private byte[] rsaSha384signature;
    private byte[] rsaSha512signature;
    private byte[] payload;
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
        rsaKeyPairGenerator.initialize(keySize);

        rsaSha256SignatureInstance = Signature.getInstance("SHA256withRSA", provider);
        rsaSha384SignatureInstance = Signature.getInstance("SHA384withRSA", provider);
        rsaSha512SignatureInstance = Signature.getInstance("SHA512withRSA", provider);

        rsaSha256VerifierInstance = Signature.getInstance("SHA256withRSA", provider);
        rsaSha384VerifierInstance = Signature.getInstance("SHA384withRSA", provider);
        rsaSha512VerifierInstance = Signature.getInstance("SHA512withRSA", provider);

        rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();

        rsaSha256SignatureInstance.initSign(rsaKeyPair.getPrivate());
        rsaSha384SignatureInstance.initSign(rsaKeyPair.getPrivate());
        rsaSha512SignatureInstance.initSign(rsaKeyPair.getPrivate());

        payload = new byte[payloadSize];
        random.nextBytes(payload);

        rsaSha256SignatureInstance.update(payload);
        rsaSha384SignatureInstance.update(payload);
        rsaSha512SignatureInstance.update(payload);

        rsaSha256signature = rsaSha256SignatureInstance.sign();
        rsaSha384signature = rsaSha384SignatureInstance.sign();
        rsaSha512signature = rsaSha512SignatureInstance.sign();
    }

    @Benchmark
    public byte[] rsaSha256Sign() throws Exception {
        rsaSha256SignatureInstance.initSign(rsaKeyPair.getPrivate());
        rsaSha256SignatureInstance.update(payload);
        return rsaSha256SignatureInstance.sign();
    }

    @Benchmark
    public byte[] rsaSha384Sign() throws Exception {
        rsaSha384SignatureInstance.initSign(rsaKeyPair.getPrivate());
        rsaSha384SignatureInstance.update(payload);
        return rsaSha384SignatureInstance.sign();
    }

    @Benchmark
    public byte[] rsaSha512Sign() throws Exception {
        rsaSha512SignatureInstance.initSign(rsaKeyPair.getPrivate());
        rsaSha512SignatureInstance.update(payload);
        return rsaSha512SignatureInstance.sign();
    }

    @Benchmark
    public boolean rsaSha256Verify() throws Exception {
        rsaSha256VerifierInstance.initVerify(rsaKeyPair.getPublic());
        rsaSha256VerifierInstance.update(payload);
        return rsaSha256VerifierInstance.verify(rsaSha256signature);
    }

    @Benchmark
    public boolean rsaSha384Verify() throws Exception {
        rsaSha384VerifierInstance.initVerify(rsaKeyPair.getPublic());
        rsaSha384VerifierInstance.update(payload);
        return rsaSha384VerifierInstance.verify(rsaSha384signature);
    }

    @Benchmark
    public boolean rsaSha512Verify() throws Exception {
        rsaSha512VerifierInstance.initVerify(rsaKeyPair.getPublic());
        rsaSha512VerifierInstance.update(payload);
        return rsaSha512VerifierInstance.verify(rsaSha512signature);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RSASignatureBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
