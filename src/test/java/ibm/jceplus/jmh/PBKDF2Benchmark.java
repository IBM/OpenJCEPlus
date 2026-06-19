/*
 * Copyright IBM Corp. 2025, 2026
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

    @Param({"OpenJCEPlus", "OpenJCEPlusFIPS", "SunJCE"})
    private String provider;

    /**
     * PBKDF2 algorithms to benchmark.
     * Non-FIPS compliant algorithms (PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA512/224, PBKDF2WithHmacSHA512/256)
     * will be skipped when provider is OpenJCEPlusFIPS.
     */
    @Param({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA512",
            "PBKDF2WithHmacSHA512/224", "PBKDF2WithHmacSHA512/256"})
    private String algorithm;

    /**
     * Iteration counts for PBKDF2.
     */
    @Param({"1000", "300000"})
    private int iterations;

    private SecretKeyFactory factory;
    private char[] password;
    private byte[] salt = new byte[16];
    private SecureRandom random = new SecureRandom();

    @Setup
    public void setup() throws Exception {
        super.setup(provider);

        // Skip non-FIPS compliant algorithms when using OpenJCEPlusFIPS provider
        if (provider.equalsIgnoreCase("OpenJCEPlusFIPS") &&
            (algorithm.equals("PBKDF2WithHmacSHA1") ||
             algorithm.equals("PBKDF2WithHmacSHA512/224") ||
             algorithm.equals("PBKDF2WithHmacSHA512/256"))) {
            throw new RunnerException("Skipping " + algorithm + " for FIPS provider");
        }

        factory = SecretKeyFactory.getInstance(algorithm, provider);

        password = "lazydogjumpedoverthemoon".toCharArray();
        random.nextBytes(salt);
    }

    @Benchmark
    public byte[] pbkdf2() throws InvalidKeySpecException {
        return factory.generateSecret(new PBEKeySpec(password, salt, iterations, 256))
                .getEncoded();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = PBKDF2Benchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
