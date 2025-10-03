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
import javax.crypto.KEM;
import javax.crypto.SecretKey;
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
public class MLKEMBenchmark extends JMHBase {

    @Param({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    private String transformation;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private KEM myKEM;
    private KeyPair keyPair;
    private KeyPairGenerator keyPairGen;
    private KEM.Encapsulator encapsulator;
    private KEM.Encapsulated encapsulated;
    private KEM.Decapsulator decapsulator;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        myKEM = KEM.getInstance(transformation, provider);
        keyPairGen = KeyPairGenerator.getInstance(transformation, provider);
        keyPair = keyPairGen.generateKeyPair();
        keyPair.getPublic();
        keyPair.getPrivate();
        encapsulator = myKEM.newEncapsulator(keyPair.getPublic());
        encapsulated = encapsulator.encapsulate(0, 31, "AES");
        decapsulator = myKEM.newDecapsulator(keyPair.getPrivate());
    }

    @Benchmark
    public SecretKey encapsulation() throws Exception {
        encapsulated = encapsulator.encapsulate(0, 31, "AES");
        return encapsulated.key();
    }

    @Benchmark
    public SecretKey decapsulation() throws Exception {
        return decapsulator.decapsulate(encapsulated.encapsulation(), 0, 31, "AES");
    }

    @Benchmark
    public SecretKey encapsulationAndDecapsulation() throws Exception {
        encapsulated = encapsulator.encapsulate(0, 31, "AES");
        return decapsulator.decapsulate(encapsulated.encapsulation(), 0, 31, "AES");
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MLKEMBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
