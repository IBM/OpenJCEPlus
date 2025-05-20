/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.MessageDigest;
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
public class MessageDigestInstanceBenchmark extends JMHBase {

    @Param({"1"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    private MessageDigest messageDigestSHA512;
    private MessageDigest messageDigestSHA256;
    private MessageDigest messageDigestMD5;
    private MessageDigest messageDigestSHA1;
    private byte[] payload;
    protected SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);
        payload = new byte[payloadSize];
        random.nextBytes(payload);
    }

    @Benchmark
    public byte[] sha512Instance() throws Exception {
        messageDigestSHA512 = MessageDigest.getInstance("SHA-512", provider);
        return messageDigestSHA512.digest(payload);
    }

    @Benchmark
    public byte[] sha256Instance() throws Exception {
        messageDigestSHA256 = MessageDigest.getInstance("SHA-256", provider);
        return messageDigestSHA256.digest(payload);
    }

    @Benchmark
    public byte[] md5Instance() throws Exception {
        messageDigestMD5 = MessageDigest.getInstance("MD5", provider);
        return messageDigestMD5.digest(payload);
    }

    @Benchmark
    public byte[] sha1Instance() throws Exception {
        messageDigestSHA1 = MessageDigest.getInstance("SHA1", provider);
        return messageDigestSHA1.digest(payload);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MessageDigestInstanceBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
