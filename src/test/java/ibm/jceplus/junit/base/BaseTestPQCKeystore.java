/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCKeystore extends BaseTestJunit5 {
    String ksName = "tmpPQCKS.pkcs12";
    File ksFile = null;
    String alias = "myalias";
    String password = "mypassword";
    FileOutputStream os = null;
    KeyStore ks =null;
    KeyPair kp = null;

    @BeforeAll
    public void setUp() throws Exception {
        try {
            ksFile = new File(ksName);
            os = new FileOutputStream(ksFile);
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null, password.toCharArray());
        } catch (Exception e) {
            System.out.println("Error setting up test: "+e.getMessage());
            throw e;
        }
    }
    @ParameterizedTest
    @CsvSource({"ML-DSA-87"})
    public void KeystoreTest(String algname) throws Exception {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algname, getProviderName());
            kp = keyPairGen.generateKeyPair(); 
    
            X509Certificate cert[] = {getSelfCertificate(algname)};

            // Add the key pair to the keystore
            ks.setKeyEntry(algname, kp.getPrivate(), password.toCharArray(), cert);
                    
            // Save the keystore to a file
            ks.store(os, password.toCharArray());
            os.close();

            System.out.println("Keystore created successfully at: " + ksFile.getAbsolutePath());

            PrivateKey tmp = (PrivateKey) ks.getKey(algname, password.toCharArray());
            X509Certificate tmpC = (X509Certificate) ks.getCertificate(algname);
            PublicKey tmpPub = tmpC.getPublicKey();

            if (tmp == null || tmpPub == null) {
                fail("Key was not gotten from keystore");
                ksFile.delete();
            }

        } catch (Exception e) {
            e.printStackTrace();
            if (ksFile.exists()){
                ksFile.delete();
            }
            throw e;
        }
        ksFile.delete();
    }

    public X509Certificate getSelfCertificate (String sigAlg)
        throws CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException {
        X509CertImpl    cert;
        Date            lastDate;
        SecureRandom    prng;

        try {
            Date firstDate = new Date ();
            lastDate = new Date ();
            lastDate.setTime (firstDate.getTime () + 360 * 1000);
            Calendar c = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
            c.setTime(lastDate);
            if (c.get(Calendar.YEAR) > 9999) {
                throw new CertificateException("Validity period ends at calendar year " +
                        c.get(Calendar.YEAR) + " which is greater than 9999");
            }

            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            X509CertInfo info = new X509CertInfo();
            // Add all mandatory attributes
            info.setVersion(new CertificateVersion(CertificateVersion.V3));
            prng = new SecureRandom();
            
            X500Name myname = new X500Name("EMAIL=sample@example.com");
            info.setSerialNumber(CertificateSerialNumber.newRandom64bit(prng));
            info.setSubject(myname);
            info.setKey(new CertificateX509Key(kp.getPublic()));
            info.setValidity(interval);
            info.setIssuer(myname);
            cert = X509CertImpl.newSigned(info, kp.getPrivate(), sigAlg);
            return cert;

        } catch (IOException e) {
            throw new CertificateEncodingException("getSelfCert: " +
                                                    e.getMessage(), e);
        }
    }
}
