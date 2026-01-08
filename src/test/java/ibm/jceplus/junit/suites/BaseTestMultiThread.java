/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.suites;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;
import static org.junit.platform.launcher.TagFilter.includeTags;

/**
 * Base abstract class for multi-threaded test suites that discover and run tests by tag.
 */
public abstract class BaseTestMultiThread {
    private final int numThreads = 10;
    private final int timeoutSec = 4500;

    public BaseTestMultiThread() {}

    /**
     * Returns the tag name to filter tests by.
     * @return the tag name
     */
    protected abstract String getTagName();

    /**
     * Returns the package name to search for tests in.
     * Currently only allow "ibm.jceplus.junit.tests".
     * @return the package name
     */
    protected String getPackageName() {
        return "ibm.jceplus.junit.tests";
    }

    protected boolean assertConcurrent(final String message, final Callable<List<TestExecutionSummary.Failure>> callable,
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

    protected Callable<List<TestExecutionSummary.Failure>> testToCallable(String className) {
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

    /**
     * Discovers all test classes with the specified tag in the specified package.
     */
    protected List<String> discoverTestClasses() {
        List<String> testClasses = new ArrayList<>();
        
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
            .selectors(selectPackage(getPackageName()))
            .filters(includeTags(getTagName()))
            .build();
        
        Launcher launcher = LauncherFactory.create();
        TestPlan testPlan = launcher.discover(request);
        
        // Collect unique test class names from the test plan
        Set<String> classNames = new java.util.HashSet<>();
        for (TestIdentifier root : testPlan.getRoots()) {
            collectTestClasses(testPlan, root, classNames);
        }
        testClasses.addAll(classNames);
        
        return testClasses;
    }
    
    /**
     * Recursively collects test class names from the test identifiers.
     */
    protected void collectTestClasses(TestPlan testPlan, TestIdentifier identifier, Set<String> classNames) {
        if (identifier.getSource().isPresent()) {
            org.junit.platform.engine.TestSource source = identifier.getSource().get();
            if (source instanceof org.junit.platform.engine.support.descriptor.ClassSource) {
                org.junit.platform.engine.support.descriptor.ClassSource classSource =
                    (org.junit.platform.engine.support.descriptor.ClassSource) source;
                classNames.add(classSource.getClassName());
            }
        }
        
        for (TestIdentifier child : testPlan.getChildren(identifier)) {
            collectTestClasses(testPlan, child, classNames);
        }
    }

    @Test
    public void testMultithread() {
        System.out.println("#threads=" + numThreads + " timeout=" + timeoutSec);
        System.out.println("Discovering tests tagged with '" + getTagName() + "' in " + getPackageName() + " package...");

        List<String> testClasses = discoverTestClasses();
        System.out.println("Found " + testClasses.size() + " test classes with " + getTagName() + " tag");
        
        if (testClasses.isEmpty()) {
            fail("No test classes found with " + getTagName() + " tag");
        }

        List<String> failedTests = new ArrayList<>();

        for (String test : testClasses) {
            try {
                System.out.println("Test calling: " + test);

                boolean failed = assertConcurrent("Test failed: " + test, testToCallable(test), timeoutSec);
                if (failed) {
                    failedTests.add(test);
                }

            } catch (InterruptedException e) {
                System.out.println("Test interrupted: " + e);
            }
            System.out.println("Test finished: " + test);
        }
        
        if (!failedTests.isEmpty()) {
            String allFailedTests = String.join("\n\t", failedTests);
            fail("Failed tests:\n\t" + allFailedTests);
        }
    }
}
