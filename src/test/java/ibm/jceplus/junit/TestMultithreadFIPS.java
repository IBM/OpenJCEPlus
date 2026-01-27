/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

public class TestMultithreadFIPS {
    private final int numThreads = 10;
    private final int timeoutSec = 4500;
    private final String[] testList = {
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCICOWithGCM",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCICOWithGCMAndAAD",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESCipherInputStreamExceptions",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESCopySafe",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMLong",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMNonExpanding",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMSameBuffer",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMUpdate",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMWithByteBuffer",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAliases",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestDESede",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestDH",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestDSAKey",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestDSASignatureInteropSUN",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestECDH",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestECDHInteropSunEC",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestECDSASignature",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHKDF",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA256",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA256InteropSunJCE",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA3_224",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA3_256",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA3_384",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA3_512",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestMiniRSAPSS2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestPBKDF2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestPBKDF2Interop",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignature",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSA_2048",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAKey",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS2",
            //"ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop3",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignatureInteropSunRsaSign",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA256Clone_SharedMD",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA3_224",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA3_256",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA3_384",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA3_512",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA512",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA512_224",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA512_256",
            //"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMWithKeyAndIvCheck", // test not in other test suites?
    };
    public final Object ob = new Object();

    public TestMultithreadFIPS() {}

    private boolean assertConcurrent(final String message, final Callable<List<TestExecutionSummary.Failure>> callable,
            final int maxTimeoutSeconds) throws InterruptedException {
        boolean failed = false;
        final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<Throwable>());
        final List<TestExecutionSummary.Failure> failures = Collections.synchronizedList(new ArrayList<TestExecutionSummary.Failure>());
        final ExecutorService threadPool = Executors.newFixedThreadPool(numThreads);
        try {
            final CountDownLatch allExecutorThreadsReady = new CountDownLatch(numThreads);
            final CountDownLatch afterInitBlocker = new CountDownLatch(1);
            final CountDownLatch allDone = new CountDownLatch(numThreads);
            for (int i = 0; i < numThreads; i++) {
                threadPool.submit(new Runnable() {
                    public void run() {
                        allExecutorThreadsReady.countDown();
                        try {
                            afterInitBlocker.await();
                            failures.addAll(callable.call());
                        } catch (final Throwable e) {
                            exceptions.add(e);
                        } finally {
                            allDone.countDown();
                        }
                    }
                });
            }
            // wait until all threads are ready
            assertTrue(
                    allExecutorThreadsReady.await(numThreads * 100, TimeUnit.MILLISECONDS),
                    "Timeout initializing threads! Perform long lasting initializations before passing runnables to assertConcurrent");
            // start all test runners
            afterInitBlocker.countDown();
            assertTrue(
                    allDone.await(maxTimeoutSeconds, TimeUnit.SECONDS),
                    message + " timeout! More than " + maxTimeoutSeconds + " seconds");
        } finally {
            threadPool.shutdownNow();
        }
        if (!exceptions.isEmpty()) {
            for (Throwable t : exceptions) {
                t.printStackTrace();
            }
        }
        failed = !exceptions.isEmpty();

        for (TestExecutionSummary.Failure failure : failures) {
            failure.getException().printStackTrace();
        }
        failed = !failures.isEmpty();

        return failed;
    }

    private Callable<List<TestExecutionSummary.Failure>> testToCallable(String className) {
        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request().
            selectors(selectClass(className)).build();
        
        Launcher launcher = LauncherFactory.create();
        launcher.discover(request);
        launcher.registerTestExecutionListeners(listener);

        return new Callable<List<TestExecutionSummary.Failure>>() {
            public List<TestExecutionSummary.Failure> call() {
                launcher.execute(request);
                return listener.getSummary().getFailures();
            }
        };
    }

    @Test
    public void testMultithreadFIPS() {
        System.out.println("#threads=" + numThreads + " timeout=" + timeoutSec);

        List<String> failedTests = new ArrayList<>();

        for (String test : testList) {
            try {
                System.out.println("Test calling: " + test);

                boolean failed = assertConcurrent("Test failed: " + test, testToCallable(test), timeoutSec);
                if (failed) {
                    failedTests.add(test);
                }

            } catch (InterruptedException e) {
                //System.out.println("Test interrupted: " + e);
            }
            System.out.println("Test finished: " + test);
            if (!failedTests.isEmpty()) {
                String allFailedTests = String.join("\n\t", failedTests);
                fail("Failed tests:\n\t" + allFailedTests);
            }
        }
    }
}
