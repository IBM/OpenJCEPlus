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
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
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
public class PBEBenchmark extends JMHBase {
    
    private Cipher pbeEncrypt, pbeDecrypt, pbeInitEncrypt;

    private byte[] salt = new byte[16];
    private SecureRandom random = new SecureRandom();
    private byte[] ivBytes = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    private byte[] text = "Bob the builder by IBM".getBytes();
    private byte[] cipherText;
    SecretKey pbeKey;

    @Param({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/256AndAES_256", "PBEWithSHA1AndDESede",
        "PBEWithSHA1AndRC2_128", "PBEWithSHA1AndRC4_128"})
    private String algorithm;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Param({"1000", "300000"})
    private int iterationCount;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);
        random.nextBytes(salt);

        pbeEncrypt = Cipher.getInstance(algorithm, provider);
        pbeKey = getKey(algorithm);
        pbeEncrypt.init(Cipher.ENCRYPT_MODE, pbeKey, new PBEParameterSpec(salt, iterationCount,
                    new IvParameterSpec(ivBytes)));
        cipherText = pbeEncrypt.doFinal(text);

        pbeDecrypt = Cipher.getInstance(algorithm, provider);
        pbeDecrypt.init(Cipher.DECRYPT_MODE, pbeKey, pbeEncrypt.getParameters());

        pbeInitEncrypt = Cipher.getInstance(algorithm, provider);
    }

    @Benchmark
    public byte[] encrypt() throws Exception {
        return pbeEncrypt.doFinal(text);
    }

    @Benchmark
    public byte[] decrypt() throws Exception {
        return pbeDecrypt.doFinal(cipherText);
    }

    @Benchmark 
    public byte[] initEncrypt() throws Exception {
        pbeInitEncrypt.init(Cipher.ENCRYPT_MODE, pbeKey, new PBEParameterSpec(salt, iterationCount,
                    new IvParameterSpec(ivBytes)));
        return pbeEncrypt.doFinal(text);
    }

    private SecretKey getKey(String algo) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec("mypassword".toCharArray());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algo, provider);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        return pbeKey;
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = PBEBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
