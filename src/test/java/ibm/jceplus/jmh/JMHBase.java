/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.openjdk.jmh.profile.ClassloaderProfiler;
import org.openjdk.jmh.profile.CompilerProfiler;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

abstract public class JMHBase {
    private List<String> allowedProviders = null;

    static Options optionsBuild(String regexClassName, String logFileRoot) {
        // This is necessary to pass various classpath values to the forked JVM we are about to create.
        URLClassLoader classLoader = (URLClassLoader) RunAll.class.getClassLoader();
        StringBuilder classpath = new StringBuilder();
        for (URL url : classLoader.getURLs()) {
            classpath.append(url.getPath()).append(File.pathSeparator);
        }
        System.setProperty("java.class.path", classpath.toString());

        // Get properties needed to build options.
        String projectHomeDir = System.getProperty("jmh.project.dir");
        String ockLibraryPath = System.getProperty("ock.library.path");
        String jgskitLibraryPath = System.getProperty("jgskit.library.path");
        String osArch = System.getProperty("os.arch", "").toLowerCase();
        String osName = System.getProperty("os.name").toLowerCase();
        String threadsProperty = System.getProperty("jmh.threads", "1");
        String allowedProv = System.getProperty("jmh.allowedProviders");
        int threads;
        try {
            threads = Integer.parseInt(threadsProperty);
            if (threads < 1) {
                throw new IllegalArgumentException("Thread count must be at least 1, got: " + threads);
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid thread count <" + threadsProperty + ">. Must be an integer.", e);
        }
        System.out.println("Home dir: " + projectHomeDir);
        System.out.println("JGSkit Library Path: " + jgskitLibraryPath);
        System.out.println("Regex of classes to run: " + regexClassName);
        System.out.println("OS Arch: " + osArch);
        System.out.println("OS Name: " + osName);
        System.out.println("Thread count: " + threads);
        System.out.println("Allowed providers: " + allowedProv);

        String logFileWithThreads = logFileRoot + "-" + threads + "t";

        OptionsBuilder optionsBuilder = new OptionsBuilder();
        optionsBuilder.threads(threads);
        optionsBuilder.include(regexClassName);
        optionsBuilder.resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON);
        optionsBuilder.result(projectHomeDir + "/target/jmh-results/" + logFileWithThreads + ".json");
        optionsBuilder.addProfiler(StackProfiler.class);
        optionsBuilder.addProfiler(GCProfiler.class);
        optionsBuilder.addProfiler(ClassloaderProfiler.class);
        
        // CompilerProfiler causes issues on ppc64le Linux which causes the Jenkins job to fail.
        // Add the compiler profiler for all other platforms.
        boolean isPpc64le = osArch.equals("ppc64le");
        boolean isLinux = osName.contains("linux");
        if (!(isPpc64le && isLinux)) {
            optionsBuilder.addProfiler(CompilerProfiler.class);
        }
        List<String> jvmArgs = new ArrayList<>(Arrays.asList("-Xms1G", "-Xmx1G", "--patch-module",
                "openjceplus=" + projectHomeDir + "/target/classes",
                "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
                "--add-exports=java.base/sun.security.pkcs=ALL-UNNAMED",
                "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
                "-Dock.library.path=" + ockLibraryPath,
                "-Djgskit.library.path=" + jgskitLibraryPath));
        if (allowedProv != null) {
            jvmArgs.add("-Djmh.allowedProviders=" + allowedProv);
        }
        optionsBuilder.jvmArgsAppend(jvmArgs.toArray(new String[0]));
        optionsBuilder.forks(1);
        optionsBuilder.output(projectHomeDir + "/target/jmh-results/" + logFileWithThreads + ".txt");

        //TODO Most Jenkins systems dont seem to work with this. Must be admin.
        /*
        if (osName.contains("linux")) {
            optionsBuilder.addProfiler(LinuxPerfProfiler.class);
            optionsBuilder.addProfiler(LinuxPerfNormProfiler.class);
            optionsBuilder.addProfiler(LinuxPerfAsmProfiler.class);
        } else if (osName.contains("windows")) {
            optionsBuilder.addProfiler(WinPerfAsmProfiler.class);
        }
        */

        //Add these conditionally based on os and arch:
        //.addProfiler(DTraceAsmProfiler.class)
        return optionsBuilder.build();
    }

    private List<String> getAllowedProviders() {
        String providers = System.getProperty("jmh.allowedProviders");
        if (providers != null) {
            return new ArrayList<>(Arrays.asList(providers.split(","))
                                         .stream()
                                         .map(p -> p.trim())
                                         .collect(Collectors.toList()));
        } else {
            return new ArrayList<>();
        }
    }

    private void logBenchmark() throws IllegalAccessException {
        // JMH auto-generates multiple subclasses of the original benchmark.
        Class<?> subClass = this.getClass();
        Class<?> originalClass = subClass.getSuperclass();
        while (originalClass != null && originalClass.getSimpleName().contains("_jmhType")) {
            originalClass = originalClass.getSuperclass();
        }
        if (originalClass != null) {
            System.out.println("Running " + originalClass.getSimpleName() + " with:");
            Field[] allFields = originalClass.getDeclaredFields();
            for (Field field : allFields) {
                field.setAccessible(true);
                if ((field.getType() == String.class)
                    || (field.getType() == int.class)
                ) {
                    System.out.println("\t" + field.getName() + " = " + field.get(this));
                }
            }
        } else {
            System.out.println("Running " + subClass.getSimpleName() + ":");
            System.out.println("\tNote: Failed to get original benchmark name");
        }
    }

    protected void setup(String provider) throws Exception {
        logBenchmark();
        
        if (allowedProviders == null) {
            allowedProviders = getAllowedProviders();
        }

        if ((!allowedProviders.isEmpty()) && !allowedProviders.contains(provider)) {
            System.out.println("Skipping provider: " + provider);
            throw new RunnerException("Skipping provider: " + provider);
        }

        insertProvider(provider);
    }

    protected void insertProvider(String provider) throws Exception {
        if (provider.equalsIgnoreCase("OpenJCEPlus")) {
            Provider myProvider = java.security.Security.getProvider("OpenJCEPlus");
            if (myProvider == null) {
                myProvider = (Provider) Class.forName("com.ibm.crypto.plus.provider.OpenJCEPlus")
                        .getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(myProvider, 1);
        } else if (provider.equalsIgnoreCase("BC")) {
            Provider myProvider = java.security.Security.getProvider("BC");
            if (myProvider == null) {
                myProvider = (Provider) Class
                        .forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                        .getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(myProvider, 1);
        }
    }
}
