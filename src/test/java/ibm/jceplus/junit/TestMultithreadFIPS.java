/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

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
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAKey",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignatureInteropSunRsaSign",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestHKDF",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestMiniRSAPSS2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMCICOWithGCMAndAAD",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMNonExpanding",
            /*"ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCMWithKeyAndIvCheck",*/
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop2",
            "ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop3"};
    public final Object ob = new Object();

    public TestMultithreadFIPS() {}

    private void assertConcurrent(final String message, final Runnable runnable,
            final int maxTimeoutSeconds) throws InterruptedException {
        final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<Throwable>());
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
                            runnable.run();
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
                    allExecutorThreadsReady.await(numThreads * 10, TimeUnit.MILLISECONDS));
            // start all test runners
            afterInitBlocker.countDown();
            assertTrue(message + " timeout! More than " + maxTimeoutSeconds + " seconds",
                    allDone.await(maxTimeoutSeconds, TimeUnit.SECONDS));
        } finally {
            threadPool.shutdownNow();
        }
        assertTrue(message + "failed with exception(s)" + exceptions, exceptions.isEmpty());
    }

    private Runnable testToRunnable(String classAndMethod) {
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
            return new Runnable() {
                public void run() {
                    Result result = new JUnitCore().run(myrequest);
                    assertTrue(result.getFailureCount()== 0);
                }
            };
        } catch (ClassNotFoundException ex) {
            assertTrue("Class not Found: " + classAndMethod, false);
        }
        return null;
    }

    public void testMultithreadFIPS() {
        System.out.println("#threads=" + numThreads + " timeout=" + timeoutSec);

        for (String test : testList) {
            try {
                System.out.println("Test calling: " + test);

                assertConcurrent("Test failed: " + test, testToRunnable(test), timeoutSec);

            } catch (InterruptedException e) {
                //System.out.println("Test interrupted: " + e);
            }
            System.out.println("Test finished: " + test);
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
