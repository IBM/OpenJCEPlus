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
    if (OCK_RELEASE == "") {
        OCK_RELEASE = "20251128_8.9.18"
    }
    def target = getOCKTarget(hardware, software)
    def gskit_bin = "https://na.artifactory.swg-devops.com/artifactory/sec-gskit-javasec-generic-local/gskit8/$OCK_RELEASE/$target/jgsk_crypto.tar"
    def gskit_sdk_bin = "https://na.artifactory.swg-devops.com/artifactory/sec-gskit-javasec-generic-local/gskit8/$OCK_RELEASE/$target/jgsk_crypto_sdk.tar"

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
            sh 'ls -laT jgsk_crypto.tar'
            sh 'chtag -b jgsk_crypto.tar'
            sh 'ls -laT jgsk_crypto.tar'
            sh 'tar -oxf jgsk_crypto.tar'
            sh 'ls -laT jgsk_crypto.tar'
            sh 'chtag -b jgsk_crypto_sdk.tar'
            sh 'ls -laT jgsk_crypto_sdk.tar'
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
        echo "Before copy folder: $jgsk8Lib"
        fileOperations([fileCopyOperation(includes: jgsk8Lib, targetLocation: 'jgsk_sdk/lib64')])
        echo "After copy folder: $jgsk8Lib"
        sh "env"

        // Additional copy is required
        if (target.contains('aix')) {
            fileOperations([fileCopyOperation(includes: jgsk8Lib, targetLocation: 'jgsk_sdk')])
        }
    }
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
    if (JAVA_RELEASE == "") {
        if (software == "zos") {
            java_link = "https://na.artifactory.swg-devops.com/artifactory/sys-rt-generic-local/hyc-runtimes-jenkins.swg-devops.com/Build_JDK25_s390x_zos_Nightly/278/ibm-semeru-certified-jdk_s390x_zos_25.0.2.0-20260225-080405.pax.Z"
        } else {
            java_link = "https://api.adoptopenjdk.net/v3/binary/latest/${JAVA_VERSION}/ga/${software}/${hardware}/jdk/openj9/normal/ibm?project=jdk"
        }
    } else {
        def java_release_link = JAVA_RELEASE.replace("+", "%2B")
        java_link = "https://api.adoptopenjdk.net/v3/binary/version/${java_release_link}/${software}/${hardware}/jdk/openj9/normal/ibm?project=jdk"
    }

    dir("java") {
        def java_file = ""
        if (software == "zos") {
            sh "curl -LJkO -u $ARTIFACTORY_USERNAME:$ARTIFACTORY_PASSWORD ${java_link}"
            java_file = sh (
                script: 'ls | grep \'pax\'',
                returnStdout: true
            ).trim()
        } else {
            sh "curl -LJkO ${java_link}"
            java_file = sh (
                script: 'ls | grep \'tar\\|zip\'',
                returnStdout: true
            ).trim()
        }

        echo "java_file: $java_file"

       if (software == "windows") {
            unzip zipFile: "$java_file"
        } else if (software =="zos") {
           sh "pax -p x -rf $java_file"
        } else {
            file: "$java_file"
        }
        sh "rm $java_file"

        def java_folder = ""
        if (software == "zos") {
            java_folder = sh (
                script: "ls | grep \'J${JAVA_VERSION}\'",
                returnStdout: true
            ).trim()
        } else {
            java_folder = sh (
                script: "ls | grep \'jdk-${JAVA_VERSION}\'",
                returnStdout: true
            ).trim()
        }
        fileOperations([folderRenameOperation(destination: 'jdk', source: "$java_folder")])

        // AIX always loads the bundled version of native libraries. We delete them to
        // ensure that the one provided by the user is utilized.
        if (software == "aix") {
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
def getMaven() {
    sh "curl -kLO https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.10/apache-maven-3.9.10-bin.tar.gz"
    untar file: "apache-maven-3.9.10-bin.tar.gz"
    sh "ls -laT apache-maven-3.9.10"
}

/*
 * Export the appropriate environment variables
 * and run the requested maven commands.
 */
def runOpenJCEPlus(command, software) {
    dir("openjceplus/OpenJCEPlus") {
        def additional_exports = ""
        if (software == "aix") {
            additional_exports = "export LIBPATH=$WORKSPACE/openjceplus/OCK/:$WORKSPACE/openjceplus/OCK/jgsk_sdk;"
        }

        def additional_envars = ADDITIONAL_ENVARS
        if (additional_envars != "") {
            for (envar in additional_envars.split(",")) {
                additional_exports += " export ${envar.trim()};"
            }

        }

        def java_home = "export JAVA_HOME=$WORKSPACE/java/jdk;"
        def gskit_home = "export GSKIT_HOME=$WORKSPACE/openjceplus/OCK/jgsk_sdk;"
        def mavenPath = "$WORKSPACE/apache-maven-3.9.10/bin"
        def environment = "export PATH=${mavenPath}:\$PATH;"

        def additional_cmd_args = ADDITIONAL_CMD_ARGS

        def ock_path = "$WORKSPACE/openjceplus/OCK/"
        if (software == "windows") {
            ock_path = "$WORKSPACE\\openjceplus\\OCK\\"
            bat """
               dir "c:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvarsall.bat"
               call "c:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvarsall.bat" x86_amd64
               set "JAVA_HOME=$WORKSPACE\\java\\jdk"
               set "PATH=$WORKSPACE\\apache-maven-3.9.10\\bin;%JAVA_HOME%;%PATH%"
               set "GSKIT_HOME=$WORKSPACE\\openjceplus\\OCK\\jgsk_sdk"
               echo PATH: %PATH%
               echo GSKIT_HOME: %GSKIT_HOME%
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
            sh "${java_home} ${gskit_home} ${additional_exports} ${environment} mvn '-Dock.library.path=${ock_path}' ${additional_cmd_args} --batch-mode ${command}"
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
    cloneOpenJCEPlus: this.&cloneOpenJCEPlus,
    runOpenJCEPlus: this.&runOpenJCEPlus,
    upload_artifactory: this.&upload_artifactory,
    getSanitizedBranchName: this.&getSanitizedBranchName,
]