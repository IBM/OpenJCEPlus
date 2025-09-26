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
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
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
public class HmacBenchmark extends JMHBase {

    @Param({"HMACSHA1", "HMACSHA256", "HMACSHA512"})
    private String transformation;

    @Param({"16", "2048", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private Mac mac;
    private byte[] payload;
    private SecretKeySpec secretKey;
    protected SecureRandom random = new SecureRandom();

    @Setup(Level.Trial)
    public void setup() throws Exception {
        insertProvider(provider);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();
        secretKey = new SecretKeySpec(key.getEncoded(), transformation);

        mac = Mac.getInstance(transformation, provider);
        mac.init(secretKey);

        payload = new byte[payloadSize];
        random.nextBytes(payload);
    }

    @Benchmark
    public byte[] hmacSingleShot() {
        return mac.doFinal(payload);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = HmacBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
