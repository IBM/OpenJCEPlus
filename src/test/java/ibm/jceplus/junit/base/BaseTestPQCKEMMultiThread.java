/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;


public class BaseTestPQCKEMMultiThread extends BaseTestJunit5 {

    private static final int THREAD_COUNT = 100;
    private static final int THREAD_POOL_SIZE = 20;
    private KEM kem = null;

    /*
     * As per JavaDoc API,
     * A KEM object is immutable. It is safe to call multiple newEncapsulator and
     * newDecapsulator methods on the same KEM object at the same time.
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    protected void testParallelEncapsulator(String algo) throws Exception {
        KeyPair kp = keyPair.gen(algo);
        kem = KEM.getInstance(algo, getProviderName());
        ExecutorService executor = null;
        try {
            executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
            CompletionService<KEM.Encapsulator> cs = new ExecutorCompletionService<>(executor);
            List<Future<KEM.Encapsulator>> futures = new ArrayList<>();

            for (int i = 0; i < THREAD_COUNT; i++) {
                Callable<KEM.Encapsulator> task = () -> kem.newEncapsulator(kp.getPublic());
                futures.add(cs.submit(task));
            }

            KEM.Decapsulator decT = kem.newDecapsulator(kp.getPrivate());
            for (Future<KEM.Encapsulator> future : futures) {
                KEM.Encapsulated enc = future.get().encapsulate();
                assertArrayEquals(decT.decapsulate(enc.encapsulation()).getEncoded(), enc.key().getEncoded(),
                                    "Secrets do NOT match");
            }
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
        }
        System.out.println("Parallel Encapsulator Test: Success");
    }

    /*
     * As per JavaDoc API,
     * Encapsulator and Decapsulator objects are also immutable.
     * It is safe to invoke multiple encapsulate and decapsulate methods on the same
     * Encapsulator or Decapsulator object at the same time.
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    protected void testParallelEncapsulate(String algo) throws Exception {
        KeyPair kp = keyPair.gen(algo);
        kem = KEM.getInstance(algo, getProviderName());
        ExecutorService executor = null;
        try {
            executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
            CompletionService<KEM.Encapsulated> cs = new ExecutorCompletionService<>(executor);
            List<Future<KEM.Encapsulated>> futures = new ArrayList<>();
            KEM.Encapsulator encT = kem.newEncapsulator(kp.getPublic());
            for (int i = 0; i < THREAD_COUNT; i++) {
                Callable<KEM.Encapsulated> task = () -> encT.encapsulate();
                futures.add(cs.submit(task));
            }
            KEM.Decapsulator decT = kem.newDecapsulator(kp.getPrivate());
            for (Future<KEM.Encapsulated> future : futures) {
                assertArrayEquals(decT.decapsulate(future.get().encapsulation()).getEncoded(),
                        future.get().key().getEncoded(), "Secrets do NOT match");
            }
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
        }
        System.out.println("Parallel Encapsulate Test: Success");
    }

    /*
     * As per JavaDoc API,
     * Encapsulator and Decapsulator objects are also immutable.
     * It is safe to invoke multiple encapsulate and decapsulate methods on the same
     * Encapsulator or Decapsulator object at the same time.
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    protected void testParallelDecapsulator(String algo) throws Exception {
        KeyPair kp = keyPair.gen(algo);
        kem = KEM.getInstance(algo, getProviderName());
        ExecutorService executor = null;
        try {
            executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
            CompletionService<KEM.Decapsulator> cs = new ExecutorCompletionService<>(executor);
            List<Future<KEM.Decapsulator>> futures = new ArrayList<>();
            for (int i = 0; i < THREAD_COUNT; i++) {
                Callable<KEM.Decapsulator> task = () -> kem.newDecapsulator(kp.getPrivate());
                futures.add(cs.submit(task));
            }

            KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate();
            for (Future<KEM.Decapsulator> decT : futures) {
                assertArrayEquals(decT.get().decapsulate(enc.encapsulation()).getEncoded(),
                        enc.key().getEncoded(), "Secrets do NOT match");
            }
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
        }
        System.out.println("Parallel Decapsulator Test: Success");
    }

    /*
     * As per JavaDoc API,
     * Encapsulator and Decapsulator objects are also immutable.
     * It is safe to invoke multiple encapsulate and decapsulate methods on the same
     * Encapsulator or Decapsulator object at the same time.
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    protected void testParallelDecapsulate(String algo) throws Exception {
        KeyPair kp = keyPair.gen(algo);
        kem = KEM.getInstance(algo, getProviderName());
        ExecutorService executor = null;
        try {
            executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
            CompletionService<SecretKey> cs = new ExecutorCompletionService<>(executor);
            KEM.Encapsulator encT = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated enc = encT.encapsulate();

            KEM.Decapsulator decT = kem.newDecapsulator(kp.getPrivate());
            List<Future<SecretKey>> futures = new ArrayList<>();
            for (int i = 0; i < THREAD_COUNT; i++) {
                Callable<SecretKey> task = () -> decT.decapsulate(enc.encapsulation());
                futures.add(cs.submit(task));
            }
            for (Future<SecretKey> future : futures) {
                assertArrayEquals(future.get().getEncoded(), enc.key().getEncoded(), "Secrets do NOT match");
            }
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
        }
        System.out.println("Parallel Decapsulate Test: Success");
    }

    @FunctionalInterface
    interface GenKeyPair<A, K> {

        K gen(A a);
    }
    private final GenKeyPair<String, KeyPair> keyPair = (algo) -> {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, getProviderName());

            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    };

}
