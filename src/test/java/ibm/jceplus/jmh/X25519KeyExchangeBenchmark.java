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
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyAgreement;
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
public class X25519KeyExchangeBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SunEC"})
    private String provider;

    private KeyPairGenerator x25519KeyPairGenerator;
    private KeyAgreement x25519KeyAgreement;
    private KeyPair bobX25519KeyPair;
    private KeyPair aliceX25519KeyPair;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        x25519KeyPairGenerator = KeyPairGenerator.getInstance("X25519", provider);
        x25519KeyAgreement = KeyAgreement.getInstance("X25519", provider);

        bobX25519KeyPair = x25519KeyPairGenerator.generateKeyPair();
        aliceX25519KeyPair = x25519KeyPairGenerator.generateKeyPair();

        x25519KeyAgreement.init(bobX25519KeyPair.getPrivate());
    }

    @Benchmark
    public byte[] x25519KeyExchange() throws Exception {
        x25519KeyAgreement.doPhase(aliceX25519KeyPair.getPublic(), true);
        return x25519KeyAgreement.generateSecret();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = X25519KeyExchangeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
