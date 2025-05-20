/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.MessageDigest;
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
public class MessageDigestBenchmark  extends JMHBase {

    @Param({"16", "2048", "32768"})
    private int dataSize;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    private MessageDigest messageDigestSHA512;
    private MessageDigest messageDigestSHA256;
    private MessageDigest messageDigestMD5;
    private MessageDigest messageDigestSHA1;
    private byte[] data;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        data = new byte[dataSize];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        messageDigestSHA512 = MessageDigest.getInstance("SHA-512", provider);
        messageDigestSHA256 = MessageDigest.getInstance("SHA-256", provider);
        messageDigestMD5 = MessageDigest.getInstance("MD5", provider);
        messageDigestSHA1 = MessageDigest.getInstance("SHA1", provider);
    }

    @Benchmark
    public byte[] sha512UpdateDigest() {
        messageDigestSHA512.update(data);
        return messageDigestSHA512.digest();
    }

    @Benchmark
    public byte[] sha256UpdateDigest() {
        messageDigestSHA256.update(data);
        return messageDigestSHA256.digest();
    }

    @Benchmark
    public byte[] md5UpdateDigest() {
        messageDigestMD5.update(data);
        return messageDigestMD5.digest();
    }

    @Benchmark
    public byte[] sha1UpdateDigest() {
        messageDigestSHA1.update(data);
        return messageDigestSHA1.digest();
    }

    @Benchmark
    public byte[] sha512SingleShotDigest() {
        return messageDigestSHA512.digest(data);
    }

    @Benchmark
    public byte[] sha256SingleShotDigest() {
        return messageDigestSHA256.digest(data);
    }

    @Benchmark
    public byte[] md5SingleShotDigest() {
        return messageDigestMD5.digest(data);
    }

    @Benchmark
    public byte[] sha1SingleShotDigest() {
        return messageDigestSHA1.digest(data);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MessageDigestBenchmark.class.getSimpleName();
        Options opt = optionsBuild(
            testSimpleName,
            testSimpleName);

        new Runner(opt).run();
    }
}
