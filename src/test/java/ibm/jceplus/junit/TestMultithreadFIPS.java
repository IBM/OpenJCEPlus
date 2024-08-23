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
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class TestMultithreadFIPS extends TestCase {
    private final int numThreads = 10;
    private final int timeoutSec = 1500;
    private final String[] testList = {"ibm.jceplus.junit.openjceplusfips.multithread.TestAliases",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMUpdate",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCopySafe",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCipherInputStreamExceptions",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCICOWithGCM",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMSameBuffer",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMWithByteBuffer",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMLong",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCM_128",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCM_192",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCM_256",*/
            "ibm.jceplus.junit.openjceplus.multithread.TestDH",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestECDH",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestECDHInteropSunEC",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestDSAKey",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAES_128",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAES_192",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAES_256",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestDESede",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestECDSASignature",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestDSASignatureInteropSUN",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestHmacMD5", */
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestHmacMD5InteropSunJCE",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA256",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA256InteropSunJCE",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA512",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestSHA256Clone_SharedMD",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignature",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestRSA_2048",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAKey",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignatureInteropSunRsaSign",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestHKDF",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestMiniRSAPSS2",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCICOWithGCMAndAAD",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMNonExpanding"//,
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMWithKeyAndIvCheck",*/
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop3"*/};
    public final Object ob = new Object();

    public TestMultithreadFIPS() {}

    private boolean assertConcurrent(final String message, final Callable<List<Failure>> callable,
            final int maxTimeoutSeconds) throws InterruptedException {
        boolean failed = false;
        final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<Throwable>());
        final List<Failure> failures = Collections.synchronizedList(new ArrayList<Failure>());
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

        for (Failure failure : failures) {
            failure.getException().printStackTrace();
        }
        failed = !failures.isEmpty();

        return failed;
    }

    private Callable<List<Failure>> testToCallable(String classAndMethod) {
        String[] classAndMethodList = classAndMethod.split("#");
        try {
            Request request = null;
            if (classAndMethodList.length == 2) {
                request = Request.method(Class.forName(classAndMethodList[0]),
                        classAndMethodList[1]);
            } else {
                request = Request.aClass(Class.forName(classAndMethodList[0]));
            }
            final Request myrequest = request;
            return new Callable<List<Failure>>() {
                public List<Failure> call() {
                    Result result = new JUnitCore().run(myrequest);
                    return result.getFailures();
                }
            };
        } catch (ClassNotFoundException ex) {
            assertTrue("Class not Found: " + classAndMethod, false);
        }
        return null;
    }

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

    public static Test suite() {
        TestSuite suite = new TestSuite(TestMultithreadFIPS.class);
        return suite;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }
}
