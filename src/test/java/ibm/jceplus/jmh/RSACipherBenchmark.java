/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
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
public class RSACipherBenchmark extends AsymmetricCipherBase {

    private Map<String, Cipher> encryptCiphers = new HashMap<>();
    private Map<String, Cipher> decryptCiphers = new HashMap<>();

    private Map<String, byte[]> plaintexts = new HashMap<>();
    private Map<String, byte[]> ciphertexts = new HashMap<>();

    @Param({"2048"})
    private int keySize;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(keySize, "RSA", provider);

        Map<String, Integer> paddings = new HashMap<>();
        paddings.put("NoPadding", 0);
        paddings.put("PKCS1Padding", 11);
        paddings.put("OAEPPadding", (2 * 20 + 2)); // SHA-1 size is 20 bytes

        for (String padding : paddings.keySet()) {
            encryptCiphers.put(padding, Cipher.getInstance("RSA/ECB/" + padding, provider));
            decryptCiphers.put(padding, Cipher.getInstance("RSA/ECB/" + padding, provider));
        }

        for (Entry<String, Integer> entry : paddings.entrySet()) {
            int payloadSize = (keySize / 8) - entry.getValue();
            byte[] plaintext = new byte[payloadSize];
            random.nextBytes(plaintext);
            plaintexts.put(entry.getKey(), plaintext);

            Cipher ec = encryptCiphers.get(entry.getKey());
            ec.init(Cipher.ENCRYPT_MODE, publicKey);

            if (plaintext.length > 0) {
                ciphertexts.put(entry.getKey(), ec.doFinal(plaintext));
            }

            Cipher dc = decryptCiphers.get(entry.getKey());
            dc.init(Cipher.DECRYPT_MODE, privateKey);
        }
    }

    @Benchmark
    public byte[] benchmarkEncryption_NoPadding() throws Exception {
        return encryptCiphers.get("NoPadding").doFinal(plaintexts.get("NoPadding"));
    }

    @Benchmark
    public byte[] benchmarkDecryption_NoPadding() throws Exception {
        return decryptCiphers.get("NoPadding").doFinal(ciphertexts.get("NoPadding"));
    }

    @Benchmark
    public byte[] benchmarkEncryption_PKCS1Padding() throws Exception {
        return encryptCiphers.get("PKCS1Padding").doFinal(plaintexts.get("PKCS1Padding"));
    }

    @Benchmark
    public byte[] benchmarkDecryption_PKCS1Padding() throws Exception {
        return decryptCiphers.get("PKCS1Padding").doFinal(ciphertexts.get("PKCS1Padding"));
    }

    @Benchmark
    public byte[] benchmarkEncryption_OAEPPadding() throws Exception {
        return encryptCiphers.get("OAEPPadding").doFinal(plaintexts.get("OAEPPadding"));
    }

    @Benchmark
    public byte[] benchmarkDecryption_OAEPPadding() throws Exception {
        return decryptCiphers.get("OAEPPadding").doFinal(ciphertexts.get("OAEPPadding"));
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = RSACipherBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
