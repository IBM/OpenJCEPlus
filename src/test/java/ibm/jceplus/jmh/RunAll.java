/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

public class RunAll extends JMHBase {

    public static void main(String[] args) throws RunnerException {
        Options opt = optionsBuild("Benchmark", // Run all classes that have the word "Benchmark" in their name.
                RunAll.class.getSimpleName());
        new Runner(opt).run();
    }
}
