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
public class DSAKeyGeneratorBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    private KeyPairGenerator dsaKeyPairGenerator1024 = null;
    private KeyPairGenerator dsaKeyPairGenerator2048 = null;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        dsaKeyPairGenerator1024 = KeyPairGenerator.getInstance("DSA", provider);
        dsaKeyPairGenerator1024.initialize(1024);
        dsaKeyPairGenerator2048 = KeyPairGenerator.getInstance("DSA", provider);
        dsaKeyPairGenerator2048.initialize(2048);
    }

    @Benchmark
    public KeyPair dsa1024KeyGeneration() throws Exception {
        return dsaKeyPairGenerator1024.generateKeyPair();
    }

    @Benchmark
    public KeyPair dsa2048KeyGeneration() throws Exception {
        return dsaKeyPairGenerator2048.generateKeyPair();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = DSAKeyGeneratorBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
