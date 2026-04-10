/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.SecureRandom;
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
public class RandomBenchmark extends JMHBase {

    @Param({"16", "2048", "32768"})
    private int payloadSize;

    private byte[] payload;

    private SecureRandom random;

    @Param({"SHA256DRBG|OpenJCEPlus", "SHA512DRBG|OpenJCEPlus", "SHA1PRNG|SUN", "DRBG|SUN"})
    private String randomToTest;

    @Setup
    public void setup() throws Exception {
        String[] algAndProvider = randomToTest.split("\\|");
        String algorithm = algAndProvider[0];
        String provider = algAndProvider[1];
        super.setup(provider);
        random = SecureRandom.getInstance(algorithm, provider);
        payload = new byte[payloadSize];
    }

    @Benchmark
    public byte[] runSecureRandom() {
        random.nextBytes(payload);
        return payload;
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RandomBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
