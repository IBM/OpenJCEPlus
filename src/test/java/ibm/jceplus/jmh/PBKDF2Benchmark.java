/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
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
public class PBKDF2Benchmark extends JMHBase {
    private SecretKeyFactory pbkdf2Sha1Factory;
    private SecretKeyFactory pbkdf2Sha256Factory;
    private SecretKeyFactory pbkdf2Sha512Factory;
    private SecretKeyFactory pbkdf2Sha512_224Factory;
    private SecretKeyFactory pbkdf2Sha512_256Factory;
    private char[] password;
    private byte[] salt = new byte[16];
    private SecureRandom random = new SecureRandom();

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        pbkdf2Sha1Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", provider);
        pbkdf2Sha256Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        pbkdf2Sha512Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", provider);
        pbkdf2Sha512_224Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512/224", provider);
        pbkdf2Sha512_256Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512/256", provider);
        password = "lazydogjumpedoverthemoon".toCharArray();
        random.nextBytes(salt);
    }

    @Benchmark
    public byte[] pbkdf2Sha11000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha1Factory.generateSecret(new PBEKeySpec(password, salt, 1000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha1300000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha1Factory.generateSecret(new PBEKeySpec(password, salt, 300000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha2561000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha256Factory.generateSecret(new PBEKeySpec(password, salt, 1000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha256300000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha256Factory.generateSecret(new PBEKeySpec(password, salt, 300000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha5121000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha512Factory.generateSecret(new PBEKeySpec(password, salt, 1000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha512300000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha512Factory.generateSecret(new PBEKeySpec(password, salt, 300000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha512_2241000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha512_224Factory.generateSecret(new PBEKeySpec(password, salt, 1000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha512_224300000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha512_224Factory.generateSecret(new PBEKeySpec(password, salt, 300000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha512_2561000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha512_256Factory.generateSecret(new PBEKeySpec(password, salt, 1000, 256))
                .getEncoded();
    }

    @Benchmark
    public byte[] pbkdf2Sha512_256300000Iter() throws InvalidKeySpecException {
        return pbkdf2Sha512_256Factory.generateSecret(new PBEKeySpec(password, salt, 300000, 256))
                .getEncoded();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = PBKDF2Benchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
