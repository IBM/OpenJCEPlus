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
import javax.crypto.spec.ChaCha20ParameterSpec;
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
public class ChaCha20CipherBenchmark extends CipherBase {

    @Param({"ChaCha20/None/NoPadding"})
    private String transformation;

    @Param({"1024", "32768"})
    private int payloadSize;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(256, transformation, payloadSize, provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, chacha20Spec);
    }

    @Benchmark
    public byte[] benchmarkEncryption() throws Exception {
        byte[] ivBytes = new byte[getIVSize("ChaCha20", "None")];
        random.nextBytes(ivBytes);
        ChaCha20ParameterSpec newChaCha20Spec = new ChaCha20ParameterSpec(ivBytes, 1);
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, newChaCha20Spec);
        return encryptCipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] benchmarkDecryption() throws Exception {
        return decryptCipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = ChaCha20CipherBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
