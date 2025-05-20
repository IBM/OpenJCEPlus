/*
 * Copyright IBM Corp. 2025
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

    private SecureRandom randomOpenJCEPlusSHA256DRBG;
    private SecureRandom randomOpenJCEPlusSHA512DRBG;
    private SecureRandom randomSUNSHA1PRNG;
    private SecureRandom randomSUNDRBG;
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        insertProvider("OpenJCEPlus");
        randomOpenJCEPlusSHA256DRBG = SecureRandom.getInstance("SHA256DRBG", "OpenJCEPlus");
        randomOpenJCEPlusSHA512DRBG = SecureRandom.getInstance("SHA512DRBG", "OpenJCEPlus");
        randomSUNSHA1PRNG = SecureRandom.getInstance("SHA1PRNG", "SUN");
        randomSUNDRBG = SecureRandom.getInstance("DRBG", "SUN");
        payload = new byte[payloadSize];
        random.nextBytes(payload);
    }

    @Benchmark
    public byte[] runOpenJCEPlusSHA256DRBG() {
        randomOpenJCEPlusSHA256DRBG.nextBytes(payload);
        return payload;
    }

    @Benchmark
    public byte[] runOpenJCEPlusSHA512DRBG() {
        randomOpenJCEPlusSHA512DRBG.nextBytes(payload);
        return payload;
    }

    @Benchmark
    public byte[] runSUNSHA1PRNG() {
        randomSUNSHA1PRNG.nextBytes(payload);
        return payload;
    }

    @Benchmark
    public byte[] runSUNDRBG() {
        randomSUNDRBG.nextBytes(payload);
        return payload;
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RandomBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
