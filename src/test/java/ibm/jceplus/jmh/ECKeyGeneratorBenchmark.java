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
import java.security.spec.ECGenParameterSpec;
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
public class ECKeyGeneratorBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SunEC"})
    private String provider;

    private KeyPairGenerator ecKeyPairGeneratorP256 = null;
    private KeyPairGenerator ecKeyPairGeneratorP384 = null;
    private KeyPairGenerator ecKeyPairGeneratorP521 = null;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        ecKeyPairGeneratorP256 = KeyPairGenerator.getInstance("EC", provider);
        ecKeyPairGeneratorP256.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPairGeneratorP384 = KeyPairGenerator.getInstance("EC", provider);
        ecKeyPairGeneratorP384.initialize(new ECGenParameterSpec("secp384r1"));
        ecKeyPairGeneratorP521 = KeyPairGenerator.getInstance("EC", provider);
        ecKeyPairGeneratorP521.initialize(new ECGenParameterSpec("secp521r1"));
    }

    @Benchmark
    public KeyPair ecP256KeyGeneration() throws Exception {
        return ecKeyPairGeneratorP256.generateKeyPair();
    }

    @Benchmark
    public KeyPair ecP384KeyGeneration() throws Exception {
        return ecKeyPairGeneratorP384.generateKeyPair();
    }

    @Benchmark
    public KeyPair ecP521KeyGeneration() throws Exception {
        return ecKeyPairGeneratorP521.generateKeyPair();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = ECKeyGeneratorBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
