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
public class MessageDigestBenchmark extends JMHBase {

    @Param({"16", "2048", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    private MessageDigest messageDigestSHA512;
    private MessageDigest messageDigestSHA512_224;
    private MessageDigest messageDigestSHA512_256;
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
        messageDigestSHA512 = MessageDigest.getInstance("SHA-512", provider);
        messageDigestSHA512_224 = MessageDigest.getInstance("SHA512/224", provider);
        messageDigestSHA512_256 = MessageDigest.getInstance("SHA512/256", provider);
        messageDigestSHA256 = MessageDigest.getInstance("SHA-256", provider);
        messageDigestMD5 = MessageDigest.getInstance("MD5", provider);
        messageDigestSHA1 = MessageDigest.getInstance("SHA1", provider);
    }

    @Benchmark
    public byte[] sha512UpdateDigest() {
        messageDigestSHA512.update(payload);
        return messageDigestSHA512.digest();
    }

    @Benchmark
    public byte[] sha512_224UpdateDigest() {
        messageDigestSHA512_224.update(payload);
        return messageDigestSHA512_224.digest();
    }

    @Benchmark
    public byte[] sha512_256UpdateDigest() {
        messageDigestSHA512_256.update(payload);
        return messageDigestSHA512_256.digest();
    }

    @Benchmark
    public byte[] sha256UpdateDigest() {
        messageDigestSHA256.update(payload);
        return messageDigestSHA256.digest();
    }

    @Benchmark
    public byte[] md5UpdateDigest() {
        messageDigestMD5.update(payload);
        return messageDigestMD5.digest();
    }

    @Benchmark
    public byte[] sha1UpdateDigest() {
        messageDigestSHA1.update(payload);
        return messageDigestSHA1.digest();
    }

    @Benchmark
    public byte[] sha512SingleShotDigest() {
        return messageDigestSHA512.digest(payload);
    }

    @Benchmark
    public byte[] sha256SingleShotDigest() {
        return messageDigestSHA256.digest(payload);
    }

    @Benchmark
    public byte[] md5SingleShotDigest() {
        return messageDigestMD5.digest(payload);
    }

    @Benchmark
    public byte[] sha1SingleShotDigest() {
        return messageDigestSHA1.digest(payload);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MessageDigestBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
