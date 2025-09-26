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
import java.security.spec.ECGenParameterSpec;
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
public class ECDHKeyExchangeBenchmark extends JMHBase {

    @Param({"OpenJCEPlus", "SunEC"})
    private String provider;

    @Param({"secp256r1", "secp384r1", "secp521r1"})
    private String curveName;

    private KeyPairGenerator ecKeyPairGenerator;
    private KeyAgreement ecdhKeyAgreement;
    private KeyPair bobECKeyPair;
    private KeyPair aliceECKeyPair;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        ecKeyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        ecKeyPairGenerator.initialize(ecSpec);

        ecdhKeyAgreement = KeyAgreement.getInstance("ECDH", provider);

        bobECKeyPair = ecKeyPairGenerator.generateKeyPair();
        aliceECKeyPair = ecKeyPairGenerator.generateKeyPair();

        ecdhKeyAgreement.init(bobECKeyPair.getPrivate());
    }

    @Benchmark
    public byte[] ecdhKeyExchange() throws Exception {
        ecdhKeyAgreement.doPhase(aliceECKeyPair.getPublic(), true);
        return ecdhKeyAgreement.generateSecret();
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = ECDHKeyExchangeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
