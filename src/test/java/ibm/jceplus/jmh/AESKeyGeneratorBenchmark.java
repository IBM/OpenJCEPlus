/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.util.concurrent.TimeUnit;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
public class AESKeyGeneratorBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private KeyGenerator aesKeyGenerator128 = null;
    private KeyGenerator aesKeyGenerator192 = null;
    private KeyGenerator aesKeyGenerator256 = null;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        aesKeyGenerator128 = KeyGenerator.getInstance("AES", provider);
        aesKeyGenerator128.init(128);
        aesKeyGenerator192 = KeyGenerator.getInstance("AES", provider);
        aesKeyGenerator192.init(192);
        aesKeyGenerator256 = KeyGenerator.getInstance("AES", provider);
        aesKeyGenerator256.init(256);
    }

    @Benchmark
    public SecretKey aes128KeyGeneration() throws Exception {
        return aesKeyGenerator128.generateKey();
    }

    @Benchmark
    public SecretKey aes192KeyGeneration() throws Exception {
        return aesKeyGenerator192.generateKey();
    }

    @Benchmark
    public SecretKey aes256KeyGeneration() throws Exception {
        return aesKeyGenerator256.generateKey();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = AESKeyGeneratorBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
