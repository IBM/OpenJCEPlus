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
public class PQCKeyGeneratorBenchmark extends JMHBase {

    @Param({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    private String algorithm;

    @Param({"OpenJCEPlus-OCK", "OpenJCEPlus-OpenSSL"})
    private String provider;

    private KeyPairGenerator keyPairGenerator;

    @Setup
    public void setup() throws Exception {
        super.setup(provider);

        keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
    }

    @Benchmark
    public KeyPair keyGeneration() throws Exception {
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = PQCKeyGeneratorBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
