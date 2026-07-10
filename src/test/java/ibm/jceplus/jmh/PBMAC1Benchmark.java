/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
public class PBMAC1Benchmark extends JMHBase {

    private SecureRandom random = new SecureRandom();
    private byte[] salt = new byte[20];
    private int iterationCount = 300000;
    private byte[] text = "Bob the builder by IBM".getBytes();
    private final char[] PASSWORD = "passwordtryagain".toCharArray();
    private SecretKey key;
    private Mac mac, mac2;

    @Param({"PBEWithHmacSHA256", "PBEWithHmacSHA384", "PBEWithHmacSHA512"})
    private String algorithm;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(provider);
        random.nextBytes(salt);

        key = new SecretKeySpec(PASSWORD.toString().getBytes(), algorithm);

        mac = Mac.getInstance(algorithm, provider);
        mac2 = Mac.getInstance(algorithm, provider);

        mac.init(key, new PBEParameterSpec(salt, iterationCount));
    }

    @Benchmark
    public byte[] generateTag() throws Exception {
        return mac.doFinal(text);
    }

    @Benchmark
    public byte[] initGenerateTag() throws Exception {
        mac2.init(key, new PBEParameterSpec(salt, iterationCount));
        return mac2.doFinal(text);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = PBMAC1Benchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
