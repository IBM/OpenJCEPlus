/*
 * Copyright IBM Corp. 2026, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
@Threads(1) // Vital: Prevents multiple clients from deadlocking a single-threaded server
public class TLSHandshakeBenchmark extends JMHBase {

    private static final int payload = 1024;
    private static final String cipherSuite = "TLS_AES_256_GCM_SHA384";

    // Hardcoded EC certificate (P-256) from BaseTestTLS.java (ecdsa_sha256 enum)
    // Source: src/test/java/ibm/jceplus/junit/base/integration/BaseTestTLS.java
    // Signature Algorithm: ecdsa-with-SHA256
    // Subject: CN = Unknown
    // Public Key Algorithm: id-ecPublicKey (P-256/secp256r1)
    private static final String EC_CERT =
            "-----BEGIN CERTIFICATE-----\n"
            + "MIIB7jCCAZWgAwIBAgIIGIixIyeIjEYwCgYIKoZIzj0EAwIwbDEQMA4GA1UEBhMH\n"
            + "VW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4G\n"
            + "A1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93\n"
            + "bjAeFw0yNDA0MTAwMDMwNTlaFw0yNTA0MTAwMDMwNTlaMGwxEDAOBgNVBAYTB1Vu\n"
            + "a25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25vd24xEDAOBgNV\n"
            + "BAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xEDAOBgNVBAMTB1Vua25vd24w\n"
            + "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARwPhB02a4D7RBqRXoBxfc2x1Z99TQB\n"
            + "WiLjIqZeHszkvhOPccQif7aDK/E+L8ur/AIb2uAHJKNwjtLsob6PHEqVoyEwHzAd\n"
            + "BgNVHQ4EFgQUZe+pp4Aw90o3yY0eW+Yp8E/wa8owCgYIKoZIzj0EAwIDRwAwRAIg\n"
            + "NB8N+LlBQK8WfPoM1xEjP+Y3+ExwOI0oIYIJ33JncMoCIEXNfzv70SKG5Nz8Zv39\n"
            + "dc7Z4hBtsoS/qhbxhlFn79UR\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * EC Private Key (P-256)
     * 
     * PrivateKeyInfo SEQUENCE (3 elem)
     * version Version INTEGER 0
     *  privateKeyAlgorithm AlgorithmIdentifier SEQUENCE (2 elem)
     *    algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
     *    parameters ANY OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
     * privateKey PrivateKey OCTET STRING (39 byte) 302502010104203D213BFBE2FEFC92DBB6957DF5B42B922894A5123C7B441951560968…
     *    SEQUENCE (2 elem)
     *        INTEGER 1
     *        OCTET STRING (32 byte) 3D213BFBE2FEFC92DBB6957DF5B42B922894A5123C7B441951560968C5E6347C
     * 
     */
    private static final String EC_PRIVATE_KEY =
            "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA9ITv74v78ktu2lX31\n"
            + "tCuSKJSlEjx7RBlRVgloxeY0fA==";

    @Param({"X25519", "X25519MLKEM768", "SecP256r1", "SecP256r1MLKEM768", "SecP384r1", "SecP384r1MLKEM1024"})
    public String namedGroup;

    @Param({"cached", "non-cached"})
    public String useCache;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private SSLServerSocket serverSocket;
    private SSLContext sslContext;
    private SSLSocketFactory clientFactory;
    private int port;
    private Thread serverThread;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        super.setup(provider);

        // Create keystore and truststore programmatically using hardcoded EC certificate
        char[] passphrase = "passphrase".toCharArray();
        
        // Generate certificate from cert string
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(
                new ByteArrayInputStream(EC_CERT.getBytes()));
        
        // Generate the private key
        PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(EC_PRIVATE_KEY));
        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey privateKey = kf.generatePrivate(priKeySpec);
        
        // Create keystore with the EC certificate and private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        Certificate[] chain = new Certificate[]{cert};
        keyStore.setKeyEntry("ec-cert", privateKey, passphrase, chain);
        
        // Create truststore with the same certificate
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("trusted-ec-cert", cert);
        
        // Initialize KeyManagerFactory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, passphrase);
        
        // Initialize TrustManagerFactory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create SSLContext with the key and trust managers
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0);

        serverSocket.setEnabledCipherSuites(new String[]{cipherSuite});
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        
        port = serverSocket.getLocalPort();
        clientFactory = sslContext.getSocketFactory();

        // Capture the current namedGroup and payload values for this trial
        final String currentNamedGroup = namedGroup;
        final int currentPayload = payload;
        
        serverThread = new Thread(() -> {
            while (!Thread.interrupted()) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    handleClient(socket, currentNamedGroup, currentPayload);
                } catch (IOException e) {
                    if (!Thread.interrupted() && !serverSocket.isClosed()) {
                        // Only log if not intentionally interrupted or socket closed
                        e.printStackTrace();
                    }
                    if (serverSocket.isClosed()) {
                        break;
                    }
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        
        Thread.sleep(500); // Wait for server to bind
    }

    @Benchmark
    public byte[] testHandshake() throws Exception {
        try (SSLSocket clientSocket = (SSLSocket) clientFactory.createSocket("localhost", port)) {
            // Set socket timeout to prevent hanging (5 minutes)
            clientSocket.setSoTimeout(300000);
            
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});

            SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(new String[]{namedGroup});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();
            
            OutputStream os = clientSocket.getOutputStream();
            InputStream is = clientSocket.getInputStream();

            os.write(new byte[payload]);
            os.flush();

            byte[] response = is.readNBytes(payload);
            
            if ("non-cached".equals(useCache)) {
                // Invalidate the session to force full handshake
                clientSocket.getSession().invalidate();
            }
            
            return response; // Prevents Dead Code Elimination
        } catch (SocketTimeoutException e) {
            System.err.println("ERROR: Client socket timeout occurred after 5 minutes - this is unexpected!");
            e.printStackTrace();
            throw e;
        }
    }

    private void handleClient(SSLSocket socket, String currentNamedGroup, int currentPayload) {
        try {
            // Set socket timeout to prevent hanging (5 minutes)
            socket.setSoTimeout(300000);
            
            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            
            // Set named groups if the method is available (Java 19+)
            SSLParameters params = socket.getSSLParameters();
            params.setNamedGroups(new String[]{currentNamedGroup});
            socket.setSSLParameters(params);
            
            socket.startHandshake();

            // Read exactly 'payload' bytes
            InputStream is = socket.getInputStream();
            byte[] buffer = is.readNBytes(currentPayload);
            
            // Write back the response
            OutputStream os = socket.getOutputStream();
            os.write(buffer);
            os.flush();
            
            socket.close();
        } catch (SocketTimeoutException e) {
            System.err.println("ERROR: Server socket timeout occurred after 5 minutes - this is unexpected!");
            e.printStackTrace();
            throw new RuntimeException("Server timeout - terminating benchmark", e);
        } catch (IOException e) {
            if (!Thread.interrupted() && !serverSocket.isClosed()) {
                e.printStackTrace();
            }
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverThread != null) {
            serverThread.join(2000);
        }
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSHandshakeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
