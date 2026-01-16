/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
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
public class RSACipherBenchmark extends AsymmetricCipherBase {

    @Param({"OAEPPADDING", "OAEPWITHSHA1ANDMGF1PADDING", "OAEPWITHSHA-1ANDMGF1PADDING",
            "OAEPWITHSHA-224ANDMGF1PADDING",
            "OAEPWITHSHA-256ANDMGF1PADDING",
            "OAEPWITHSHA-384ANDMGF1PADDING",
            "OAEPWITHSHA-512ANDMGF1PADDING",
            "OAEPWITHSHA-512/224ANDMGF1PADDING",
            "OAEPWITHSHA-512/256ANDMGF1PADDING",
            "NOPADDING", "PKCS1PADDING"})
    private String padding;

    @Param({"2048"})
    private int keySize;

    @Param({"53", "126"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(keySize, padding, payloadSize, provider);
    }

    @Setup(Level.Invocation)
    public void setupInvocation() throws Exception {
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    @Benchmark
    public byte[] benchmarkEncryption() throws Exception {
        return encryptCipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] benchmarkDecryption() throws Exception {
        return decryptCipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RSACipherBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
