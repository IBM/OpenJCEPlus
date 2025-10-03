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
public class RSAKeyGeneratorBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SunRsaSign"})
    private String provider;

    private KeyPairGenerator rsaKeyPairGenerator1024 = null;
    private KeyPairGenerator rsaKeyPairGenerator2048 = null;
    private KeyPairGenerator rsaKeyPairGenerator4096 = null;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        rsaKeyPairGenerator1024 = KeyPairGenerator.getInstance("RSA", provider);
        rsaKeyPairGenerator1024.initialize(1024);
        rsaKeyPairGenerator2048 = KeyPairGenerator.getInstance("RSA", provider);
        rsaKeyPairGenerator2048.initialize(2048);
        rsaKeyPairGenerator4096 = KeyPairGenerator.getInstance("RSA", provider);
        rsaKeyPairGenerator4096.initialize(4096);
    }

    @Benchmark
    public KeyPair rsa1024KeyGeneration() throws Exception {
        return rsaKeyPairGenerator1024.generateKeyPair();
    }

    @Benchmark
    public KeyPair rsa2048KeyGeneration() throws Exception {
        return rsaKeyPairGenerator2048.generateKeyPair();
    }

    @Benchmark
    public KeyPair rsa4096KeyGeneration() throws Exception {
        return rsaKeyPairGenerator4096.generateKeyPair();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RSAKeyGeneratorBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
