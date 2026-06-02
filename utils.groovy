/*
 * Checks whether OpenJCEPlus is buildable on this platform.
 *
 * @return  Whether OpenJCEPlus is buildable on the platform
 */
def isBuildable(hardware, software) {
    return ((software == "aix")
        || ((software == "linux") && ((hardware == "x86-64")
                                   || (hardware == "ppc64le")
                                   || (hardware == "s390x")
                                   || (hardware == "aarch64")))
        || ((software == "mac") && ((hardware == "aarch64")
                                 || (hardware == "x86-64")))
        || ((software == "windows") && (hardware == "x86-64")))

}

/*
 * Get the proper representation of the platform for OCK.
 *
 * @return  The proper representation of the platform for OCK
 */
def getOCKTarget(hardware, software) {
    def target = ""

    /*
     * Based on the specific hardware and software, pick the
     * appropriate option to use when getting OCK binaries to
     * set up the environment for the build.
     */
    if (software == "aix") {
        target = "aix64_ppc"
    } else if (software == "linux") {
        if (hardware == "x86-64") {
            target = "linux64_x86"
        } else if (hardware == "ppc64le") {
            target = "linux64_ppcle"
        } else if (hardware == "s390x") {
            target = "linux64_s390"
        } else if (hardware == "aarch64") {
            target = "linux64_arm"
        }
    } else if (software == "mac") {
        if (hardware == "aarch64") {
            target = "osx64_arm"
        } else if (hardware == "x86-64") {
            target = "osx64_x86"
        }
    } else if (software == "windows") {
        if (hardware == "x86-64") {
            target = "win64_x86"
        }
    } else if (software == "zos") {
        target = "zos64a"
    }

    return target
}

/*
 * Figure out the proper URL, get the OCK binaries,
 * extract them and copy the files to the required
 * locations.
 */
def getBinaries(hardware, software) {
    def ockRelease = OCK_RELEASE
    if (ockRelease == "") {
        if (hardware == "s390x") { // covers LoZ and z/OS
            ockRelease = "20260219_8.9.21"
        } else {
            ockRelease = "20251128_8.9.18"
        }
    }
    def target = getOCKTarget(hardware, software)
    def gskit_bin = "https://na.artifactory.swg-devops.com/artifactory/sec-gskit-javasec-generic-local/gskit8/$ockRelease/$target/jgsk_crypto.tar"
    def gskit_sdk_bin = "https://na.artifactory.swg-devops.com/artifactory/sec-gskit-javasec-generic-local/gskit8/$ockRelease/$target/jgsk_crypto_sdk.tar"

    // If user has specified OCK_FULL_URL, override default location.
    def ockUrl = OCK_FULL_URL
    if (ockUrl != "") {
        gskit_bin = "${ockUrl}/jgsk_crypto.tar"
        gskit_sdk_bin = "${ockUrl}/jgsk_crypto_sdk.tar"
    }
    dir("openjceplus/OCK") {
        withCredentials([usernamePassword(credentialsId: '7c1c2c28-650f-49e0-afd1-ca6b60479546', passwordVariable: 'GSKIT_PASSWORD', usernameVariable: 'GSKIT_USERNAME')]) {
            sh "curl -k -u $GSKIT_USERNAME:$GSKIT_PASSWORD $gskit_bin -o jgsk_crypto.tar"
            sh "curl -k -u $GSKIT_USERNAME:$GSKIT_PASSWORD $gskit_sdk_bin -o jgsk_crypto_sdk.tar"
        }
        if (software == "zos") {
            sh 'chtag -b jgsk_crypto.tar'
            sh 'tar -oxf jgsk_crypto.tar'
            sh 'chtag -b jgsk_crypto_sdk.tar'
            sh 'tar -oxf jgsk_crypto_sdk.tar'
        } else {
            untar file: 'jgsk_crypto.tar'
            untar file: 'jgsk_crypto_sdk.tar'
        }

        def jgsk8Lib = 'libjgsk8iccs_64.so'
        if (target.contains('osx')) {
            jgsk8Lib = 'libjgsk8iccs.dylib'
        } else if (target.contains('win')) {
            jgsk8Lib = 'jgsk8iccs_64.dll'
        }
        fileOperations([fileCopyOperation(includes: jgsk8Lib, targetLocation: 'jgsk_sdk/lib64')])

        // Additional copy is required
        if (target.contains('aix')) {
            fileOperations([fileCopyOperation(includes: jgsk8Lib, targetLocation: 'jgsk_sdk')])
        }
    }
}

/*
 * Returns the Artifactory URL for a custom/workaround JDK build. This method serves as
 * an alternative method for bootstrapping our builds when official builds wont work
 * from official GA releases from AdoptOpenJDK API.
 */
def getJavaWorkaroundUrl(artifactoryPath, hardware, software, javaRelease) {
    def java_link = ""
    def baseUrl = "https://na.artifactory.swg-devops.com/artifactory/sys-rt-generic-local/${artifactoryPath}"

    def filename = ""
    if (software == "windows") {
        filename = "ibm-semeru-open-jdk_x64_windows_${javaRelease}JDK26U_2026-01-02-02-41.zip"
    } else if ((software == "linux") && (hardware == "aarch64")) {
        filename = "ibm-semeru-open-jdk_aarch64_linux_${javaRelease}JDK26U_2026-01-03-18-27.tar.gz"
    } else if ((software == "linux") && (hardware == "ppc64le")) {
        filename = "ibm-semeru-open-jdk_ppc64le_linux_${javaRelease}JDK26U_2026-01-03-18-27.tar.gz"
    } else if ((software == "linux") && (hardware == "x64")) {
        filename = "ibm-semeru-open-jdk_x64_linux_${javaRelease}JDK26U_2026-01-02-02-41.tar.gz"
    } else if ((software == "linux") && (hardware == "s390x")) {
        filename = "ibm-semeru-open-jdk_s390x_linux_${javaRelease}JDK26U_2026-01-03-18-27.tar.gz"
    } else if ((software == "mac") && (hardware == "aarch64")) {
        filename = "ibm-semeru-open-jdk_aarch64_mac_${javaRelease}JDK26U_2026-01-03-18-27.tar.gz"
    } else if ((software == "mac") && (hardware == "x64")) {
        filename = "ibm-semeru-open-jdk_x64_mac_${javaRelease}JDK26U_2026-01-03-18-27.tar.gz"
    } else if (software == "aix") {
        filename = "ibm-semeru-open-jdk_ppc64_aix_${javaRelease}JDK26U_2026-01-03-18-27.tar.gz"
    }

    if (filename != "") {
        java_link = "${baseUrl}/${filename}"
    }

    return java_link
}

/*
 * Constructs the appropriate Semeru JDK download URL based on the Java version,
 * hardware platform, and software OS. Supports both latest GA releases and
 * specific version releases using the AdoptOpenJDK API.
 */
def getJavaDownloadUrl(javaVersion, hardware, software, javaRelease) {
    def java_link = ""

    if (javaRelease == "") {
        // Use latest GA version
        java_link = "https://api.adoptopenjdk.net/v3/binary/latest/${javaVersion}/ga/${software}/${hardware}/jdk/openj9/normal/ibm?project=jdk"
        if (software == "zos") {
            java_link = "https://na.artifactory.swg-devops.com/artifactory/sys-rt-generic-local/hyc-runtimes-jenkins.swg-devops.com/Build_JDK25_s390x_zos_Nightly/278/ibm-semeru-certified-jdk_s390x_zos_25.0.2.0-20260225-080405.pax.Z"
        }
    } else {
        // Use specific version
        def java_release_link = javaRelease.replace("+", "%2B")
        java_link = "https://api.adoptopenjdk.net/v3/binary/version/${java_release_link}/${software}/${hardware}/jdk/openj9/normal/ibm?project=jdk"
    }

    return java_link
}

/*
 * Figure out the proper URL, get the Semeru JDK,
 * extract it and rename the containing folder to
 * be used later on.
 */
def getJava(hardware, software) {
    def extension = "tar.gz"
    if (software == "windows") {
        extension = "zip"
    }

    if (hardware == "x86-64") {
        hardware = "x64"
    }

    def java_link = ""

    // Check if JAVA_RELEASE is a URL that contains artifactory.
    if (JAVA_RELEASE.contains("https://na.artifactory.swg-devops.com")) {
        // JAVA_RELEASE is an Artifactory URL
        java_link = JAVA_RELEASE
        echo "Using Artifactory URL from JAVA_RELEASE: ${java_link}"
    } else if (JAVA_RELEASE.startsWith("http://") || JAVA_RELEASE.startsWith("https://")) {
        // JAVA_RELEASE is a URL but not from Artifactory - fail the build
        error("JAVA_RELEASE contains a URL that is not from na.artifactory.swg-devops.com. Only Artifactory URLs are supported.")
    } else {
        // JAVA_RELEASE is a version string or empty - use the API
        java_link = getJavaDownloadUrl(JAVA_VERSION, hardware, software, JAVA_RELEASE)
        echo "Using AdoptOpenJDK API URL: ${java_link}"
    }

    // Determine file extension based on platform
    def file_extension = "tar.gz"
    if (software == "windows") {
        file_extension = "zip"
    }

    // Use workaround URL from Artifactory, if official builds don't work
    //def java_link = getJavaWorkaroundUrl("openjceplusworkaround050126", hardware, software, JAVA_RELEASE)

    dir("java") {
        def java_file = ""
        // Download Java - use credentials if it's an Artifactory URL
        if (JAVA_RELEASE.contains("na.artifactory.swg-devops.com")) {
            java_file = "java.${file_extension}"
            withCredentials([usernamePassword(credentialsId: '7c1c2c28-650f-49e0-afd1-ca6b60479546', passwordVariable: 'ARTIFACTORY_PASSWORD', usernameVariable: 'ARTIFACTORY_USERNAME')]) {
                sh "curl -u \$ARTIFACTORY_USERNAME:\$ARTIFACTORY_PASSWORD ${java_link} > ${java_file}"
            }
        } else if (software == "zos") {
            sh "curl -LJkO -u $ARTIFACTORY_USERNAME:$ARTIFACTORY_PASSWORD ${java_link}"
            java_file = sh (
                script: 'ls | grep \'pax\'',
                returnStdout: true
            ).trim()

            // We also need to download a java.base patch to disabled checking for signed JARs or else we can't do a patch-module.
            sh "curl -LJkO -u $ARTIFACTORY_USERNAME:$ARTIFACTORY_PASSWORD https://na.artifactory.swg-devops.com/artifactory/sys-rt-generic-local/openjceplusworkaroundzos032526/java.base.jar"
        } else {
            sh "curl -LJkO ${java_link}"
            java_file = sh (
                script: 'ls | grep \'tar\\|zip\'',
                returnStdout: true
            ).trim()
        }

       if (software == "windows") {
            unzip zipFile: "$java_file"
        } else if (software =="zos") {
           sh "pax -p x -rf $java_file"
        } else {
            untar file: "$java_file"
        }
        sh "rm $java_file"

        // Check if folder is already named 'jdk' (Artifactory downloads) or needs renaming
        def folderCheck = sh (
            script: "ls -d jdk 2>/dev/null || echo ''",
            returnStdout: true
        ).trim()

        if (folderCheck == "") {
            // Folder is not named 'jdk', so find and rename it
            def java_prefix = "jdk-"
            if (software == "zos") {
                java_prefix = "J"
            }
            def java_folder = sh (
                script: "ls | grep \'${java_prefix}${JAVA_VERSION}\'",
                returnStdout: true
            ).trim()
            fileOperations([folderRenameOperation(destination: 'jdk', source: "$java_folder")])
        } else {
            echo "Java folder already named 'jdk', no rename needed"
        }

        // AIX and z/OS always loads the bundled version of native libraries. We delete them to
        // ensure that the one provided by the user is utilized.
        if (software == "aix" || software == "zos") {
            fileOperations([fileDeleteOperation(excludes: '', includes: 'jdk/lib/libjgsk8iccs_64.so'),
                            fileDeleteOperation(excludes: '', includes: 'jdk/lib/libjgskit.so'),
                            folderDeleteOperation('jdk/lib/C'),
                            folderDeleteOperation('jdk/lib/N')])
        }
    }
}

/*
 * Get the Maven tool and extract it.
 */
def getMaven(software) {
    sh "curl -kLO https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.10/apache-maven-3.9.10-bin.tar.gz"
    untar file: "apache-maven-3.9.10-bin.tar.gz"
    if (software == "zos") {
        sh "chtag -tR -c ISO8859-1 apache-maven-3.9.10"
    }
}

def getOpenSSL(hardware, software) {
    def version = "openssl-4.0.0"
    def platform = "${hardware}_${software}"
    //sh "git clone -b ${version} https://github.com/openssl/openssl.git"

    openssl_link = "https://na.artifactory.swg-devops.com/artifactory/sys-rt-generic-local/OpenSSL_builds/${platform}/${version}/${platform}-${version}.tar.gz"
    withCredentials([usernamePassword(credentialsId: '7c1c2c28-650f-49e0-afd1-ca6b60479546', passwordVariable: 'ARTIFACTORY_PASSWORD', usernameVariable: 'ARTIFACTORY_USERNAME')]) {
        // -s: silent, -o: output to null, -w: write-out the status code, -I: HEAD request
        def status = sh(script: "curl -u \$ARTIFACTORY_USERNAME:\$ARTIFACTORY_PASSWORD -s -o /dev/null -w '%{http_code}' -I ${openssl_link}", returnStdout: true).trim()
        if (status == "200") {
            echo "OpenSSL version ${version} already exists."
            sh "curl -u \$ARTIFACTORY_USERNAME:\$ARTIFACTORY_PASSWORD ${openssl_link} > openssl.tar.gz"
            dir("openssl") {
                sh "tar -xvf ../openssl.tar.gz --strip-components=2"
                sh "ls -la"
            }
        } else {
            stage('Trigger Parameterized Job') {
                    build job: 'Security/job/OpenSSL-Build-Install-Compress',
                        wait: true, // Set to true if you want this stage to block until the child job finishes
                        propagate: true, // Set to false so the parent job doesn't fail if the child job fails
                        parameters: [
                            string(name: 'TAGS', value: version),
                            booleanParam(name: 'PLATFORMS', value: platform)
                        ]
            }
            error("OpenSSL version ${version} does not exist. Need to build.")
        }
    }

}

/*
 * Export the appropriate environment variables
 * and run the requested maven commands.
 */
def runOpenJCEPlus(command, software) {
    dir("openjceplus/OpenJCEPlus") {
        def additional_exports = ""
        if (software == "aix" || software == "zos") {
            additional_exports = "export LIBPATH=$WORKSPACE/openjceplus/OCK/:$WORKSPACE/openjceplus/OCK/jgsk_sdk;"
        }
        if (software == "zos") {
            additional_exports += "export JAVA_TOOL_OPTIONS=\"-Dstdout.encoding=IBM-1047 " +
                                            "-Dstderr.encoding=IBM-1047 " +
                                            "--patch-module=java.base=\"$WORKSPACE/java/java.base.jar\" " +
                                            "\";"
        }

        def additional_envars = ADDITIONAL_ENVARS
        if (additional_envars != "") {
            for (envar in additional_envars.split(",")) {
                additional_exports += " export ${envar.trim()};"
            }
        }

        def java_home = "export JAVA_HOME=$WORKSPACE/java/jdk;"
        def gskit_home = "export GSKIT_HOME=$WORKSPACE/openjceplus/OCK/jgsk_sdk;"
        def openssl_home = "export OPENSSL_HOME=$WORKSPACE/openssl;"
        def mavenPath = "$WORKSPACE/apache-maven-3.9.10/bin"
        def environment = "export PATH=${mavenPath}:\$PATH;"

        def additional_cmd_args = ADDITIONAL_CMD_ARGS

        def ock_path = "$WORKSPACE/openjceplus/OCK/"
        def openssl_path = "$WORKSPACE/openssl/lib/"
        if (software == "windows") {
            ock_path = "$WORKSPACE\\openjceplus\\OCK\\"
            bat """
               dir "c:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvarsall.bat"
               call "c:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvarsall.bat" x86_amd64
               set "JAVA_HOME=$WORKSPACE\\java\\jdk"
               set "PATH=$WORKSPACE\\apache-maven-3.9.10\\bin;%JAVA_HOME%;%PATH%"
               set "GSKIT_HOME=$WORKSPACE\\openjceplus\\OCK\\jgsk_sdk"
               set "OPENSSL_HOME=$WORKSPACE\\openssl"
               echo PATH: %PATH%
               echo GSKIT_HOME: %GSKIT_HOME%
               echo OPENSSL_HOME: %OPENSSL_HOME%
               echo JAVA_HOME: %JAVA_HOME%
               echo mvn -Dock.library.path=${ock_path} --batch-mode ${command}
               $WORKSPACE\\apache-maven-3.9.10\\bin\\mvn -Dock.library.path=${ock_path} ${additional_cmd_args} --batch-mode ${command}
               """
        } else if (software == "mac") {
            java_home = "export JAVA_HOME=$WORKSPACE/java/jdk/Contents/Home;"
        } else if (software == "aix") {
            environment = "export PATH=/opt/IBM/openxlC/17.1.3/bin:/opt/IBM/openxlC/17.1.3/tools:/opt/IBM/openxlC/17.1.3/compat/llvm:${mavenPath}:\$PATH;"
        }

        if (software != "windows") {
            sh "${java_home} ${gskit_home} ${openssl_home} ${additional_exports} ${environment} mvn '-Dock.library.path=${ock_path}' ${additional_cmd_args} --batch-mode ${command}"
        }
    }
}

/*
 * Upload the compressed build into Artifactory.
 *
 * @param uploadSpec    This is the struct containing the upload specification
 * @return              The URL of the server used to upload
 */
def upload_artifactory(uploadSpec) {
    echo "Uploading to artifactory..."
    // Specify the Artifactory server to be used.
    def server = Artifactory.server 'na-public.artifactory.swg-devops'
    // Set connection timeout to 10 mins to avoid timeout on slow platforms.
    server.connection.timeout = 600

    // Create build info for this pipeline.
    def buildInfo = Artifactory.newBuildInfo()
    buildInfo.retention maxBuilds: 30, maxDays: 60, deleteBuildArtifacts: true
    buildInfo.env.capture = true
    buildInfo.name = "sys-rt/" + buildInfo.name

    // Upload to Artifactory and retry  if errors occur
    def ret = false
    retry(3) {
        if (ret) {
            sleep time: 300, unit: 'SECONDS'
        } else {
            ret = true
        }
        server.upload spec: uploadSpec, buildInfo: buildInfo
        server.publishBuildInfo buildInfo
    }

    return server.getUrl()
}

/*
 * Returns a formatted directory name based upon a branch name.
 */
def getSanitizedBranchName() {
    SANITIZED_BRANCH_NAME=sh(
        script: "echo $env.BRANCH_NAME | tr -c '[:alpha:][:digit:][.]' '-' | tr -d '\r\n' | sed 's/.\$//'",
        returnStdout: true
    ).trim()
    return SANITIZED_BRANCH_NAME
}

return [
    getPlatforms: this.&getPlatforms,
    isBuildable: this.&isBuildable,
    getOCKTarget: this.&getOCKTarget,
    getBinaries: this.&getBinaries,
    getJava: this.&getJava,
    getMaven: this.&getMaven,
    getOpenSSL: this.&getOpenSSL,
    cloneOpenJCEPlus: this.&cloneOpenJCEPlus,
    runOpenJCEPlus: this.&runOpenJCEPlus,
    upload_artifactory: this.&upload_artifactory,
    getSanitizedBranchName: this.&getSanitizedBranchName,
]