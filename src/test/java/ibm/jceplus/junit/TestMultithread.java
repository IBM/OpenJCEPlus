/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
import junit.framework.TestCase;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

public class TestMultithread extends TestCase {
    private final int numThreads = 10;
    private final int timeoutSec = 3000;
    private final String[] testList = {
            "ibm.jceplus.junit.openjceplus.multithread.TestAES_128",
            "ibm.jceplus.junit.openjceplus.multithread.TestAES_192",
            "ibm.jceplus.junit.openjceplus.multithread.TestAES_256",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCM_128",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCM_192",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCM_256",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMCICOWithGCM",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMCICOWithGCMAndAAD",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESCipherInputStreamExceptions",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMCopySafe",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMLong",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMNonExpanding",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMSameBuffer",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMUpdate",
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMWithByteBuffer",
            "ibm.jceplus.junit.openjceplus.multithread.TestAliases",
            "ibm.jceplus.junit.openjceplus.multithread.TestDESede",
            "ibm.jceplus.junit.openjceplus.multithread.TestDH",
            "ibm.jceplus.junit.openjceplus.multithread.TestDSAKey",
            "ibm.jceplus.junit.openjceplus.multithread.TestDSASignatureInteropSUN",
            "ibm.jceplus.junit.openjceplus.multithread.TestECDH",
            "ibm.jceplus.junit.openjceplus.multithread.TestECDHInteropSunEC",
            "ibm.jceplus.junit.openjceplus.multithread.TestECDSASignature",
            "ibm.jceplus.junit.openjceplus.multithread.TestEdDSASignature",
            "ibm.jceplus.junit.openjceplus.multithread.TestHKDF",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacMD5",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacMD5InteropSunJCE",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA256",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA256InteropSunJCE",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA3_224",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA3_256",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA3_384",
            "ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA3_512",
            "ibm.jceplus.junit.openjceplus.multithread.TestMiniRSAPSS2",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSASignature",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSA_2048",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSAKey",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSAPSS",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSAPSS2",
            //"ibm.jceplus.junit.openjceplus.multithread.TestRSAPSSInterop2",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSAPSSInterop3",
            "ibm.jceplus.junit.openjceplus.multithread.TestRSASignatureInteropSunRsaSign",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA256Clone_SharedMD",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA3_224",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA3_256",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA3_384",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA3_512",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA512",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA512_224",
            "ibm.jceplus.junit.openjceplus.multithread.TestSHA512_256",
            "ibm.jceplus.junit.openjceplus.multithread.TestXDH",
            "ibm.jceplus.junit.openjceplus.multithread.TestXDHKeyImport",
            "ibm.jceplus.junit.openjceplus.multithread.TestXDHKeyPairGenerator",
            "ibm.jceplus.junit.openjceplus.multithread.TestXDHMultiParty"};

    public TestMultithread() {}

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
                    "Timeout initializing threads! Perform long lasting initializations before passing runnables to assertConcurrent",
                    allExecutorThreadsReady.await(numThreads * 50, TimeUnit.MILLISECONDS));
            // start all test runners
            afterInitBlocker.countDown();
            assertTrue(message + " timeout! More than " + maxTimeoutSeconds + " seconds",
                    allDone.await(maxTimeoutSeconds, TimeUnit.SECONDS));
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

    public void testMultithread() {
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
