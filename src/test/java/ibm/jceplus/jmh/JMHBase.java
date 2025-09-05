/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.jmh;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Provider;
import org.openjdk.jmh.profile.ClassloaderProfiler;
import org.openjdk.jmh.profile.CompilerProfiler;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

abstract public class JMHBase {

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
        String osName = System.getProperty("os.name").toLowerCase();
        System.out.println("Home dir: " + projectHomeDir);
        System.out.println("JGSkit Library Path: " + jgskitLibraryPath);
        System.out.println("Regex of classes to run: " + regexClassName);
        System.out.println("OS Name: " + osName);

        OptionsBuilder optionsBuilder = new OptionsBuilder();
        optionsBuilder.include(regexClassName);
        optionsBuilder.resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON);
        optionsBuilder.result(projectHomeDir + "/target/jmh-results/" + logFileRoot + ".json");
        optionsBuilder.addProfiler(StackProfiler.class);
        optionsBuilder.addProfiler(GCProfiler.class);
        optionsBuilder.addProfiler(ClassloaderProfiler.class);
        optionsBuilder.addProfiler(CompilerProfiler.class);
        optionsBuilder.jvmArgsAppend("-Xms1G", "-Xmx1G", "--patch-module",
                "openjceplus=" + projectHomeDir + "/target/classes",
                "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
                "--add-exports=java.base/sun.security.pkcs=ALL-UNNAMED",
                "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
                "-Dock.library.path=" + ockLibraryPath,
                "-Djgskit.library.path=" + jgskitLibraryPath);
        optionsBuilder.forks(1);
        optionsBuilder.output(projectHomeDir + "/target/jmh-results/" + logFileRoot + ".txt");

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
