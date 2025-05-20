/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyAgreement;
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
public class DHKeyExchangeBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    @Param({"1024", "4096"})
    private int keySize;

    private KeyPairGenerator dhKeyPairGenerator;
    private KeyAgreement dhKeyAgreement;
    private KeyPair bobDHKeyPair;
    private KeyPair aliceDHKeyPair;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        dhKeyPairGenerator = KeyPairGenerator.getInstance("DH", provider);
        dhKeyPairGenerator.initialize(keySize);

        dhKeyAgreement = KeyAgreement.getInstance("DH", provider);

        bobDHKeyPair = dhKeyPairGenerator.generateKeyPair();
        aliceDHKeyPair = dhKeyPairGenerator.generateKeyPair();

        dhKeyAgreement.init(bobDHKeyPair.getPrivate());
    }

    @Benchmark
    public byte[] dhKeyExchange() throws Exception {
        dhKeyAgreement.doPhase(aliceDHKeyPair.getPublic(), true);
        return dhKeyAgreement.generateSecret();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = DHKeyExchangeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
