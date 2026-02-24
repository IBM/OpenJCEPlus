/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.Key;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
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
public class AESWrapBenchmark extends SymmetricCipherBase {

    @Param({"AESWrap", "AESWrapPad"})
    private String transformation;

    @Param({"128", "192", "256"})
    private int keySize;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private byte[] wrappedKey;

    @Setup
    public void setup() throws Exception {
        super.setup(keySize, transformation, 0, provider);
        encryptCipher.init(Cipher.WRAP_MODE, secretKey);
        decryptCipher.init(Cipher.UNWRAP_MODE, secretKey);
        wrappedKey = encryptCipher.wrap(secretKey);
    }

    @Benchmark
    public byte[] benchmarkAESWrap() throws Exception {
        return encryptCipher.wrap(secretKey);
    }

    @Benchmark
    public Key benchmarkAESUnwrap() throws Exception {
        return decryptCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = AESWrapBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
