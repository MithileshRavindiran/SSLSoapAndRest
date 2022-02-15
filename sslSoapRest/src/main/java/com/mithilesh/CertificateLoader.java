package nl.rabobank.cashservices.cla.common;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.naming.ConfigurationException;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Collections;

@Slf4j
public class CertificateLoader {

    private static final String TEMPORARY_KEY_PASSWORD = "changeit";

    public static void main(String[] args) throws ConfigurationException, KeyStoreException {
        //Key Store Default version
       KeyStore keyStore = getKeyStore();
       //AWS Lambda Key store update --working with rds.root.pem
        KeyStore lambdaKeyStore = getKeyStore();

        System.out.println(keyStore);
        X509Certificate[] certificates = getX509Certificates(keyStore);
        System.out.println(certificates.length);
    }

    private static KeyStore trustStoreUpdate() throws IOException, GeneralSecurityException, URISyntaxException {
        File file = getFile("rds-ca-2019-root.pem");
        Certificate clientCertificate = loadCertificate(file);
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        System.out.println(filename);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, "changeit".toCharArray());
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        //Input stream to cert file
//        Certificate caCert = cf.generateCertificate(IOUtils.toInputStream("cacert", Charset.defaultCharset()));
//        keyStore.setCertificateEntry("ca-cert", caCert);
        //keyStore.setCertificateEntry("ca-cert", caCertificate);
        keyStore.setCertificateEntry("client-cert", clientCertificate);

        String certPath = "/tmp/CustomTruststore";

        try (FileOutputStream out = new FileOutputStream(certPath)) {
            keyStore.store(out, "MyPass".toCharArray());
        }

        System.setProperty("javax.net.ssl.trustStore", certPath);
        System.setProperty("javax.net.ssl.trustStorePassword","MyPass");
        System.out.println("Updated the Trust Store");
        return keyStore;
    }

    public static X509Certificate[] getX509Certificates(KeyStore keyStore) throws KeyStoreException {
        return Collections.list(keyStore.aliases())
                .stream()
                .filter(t -> {
                    System.out.println(t);
                    try {
                        return isCertificateEntry(keyStore, t);
                    } catch (Exception e) {
                        e.printStackTrace();
                        return false;
                    }
                })
                .map(t -> {
                    try {
                        Certificate certificate = getCertificate(keyStore, t);
                        System.out.println(certificate.toString());
                        return certificate;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                })
                .toArray(X509Certificate[]::new);
    }

    public static Certificate getCertificate(KeyStore keyStore, String t) throws Exception {
        try {
            log.info("TrustStore status = collecting certs from truststore");
            return keyStore.getCertificate(t);
        } catch (KeyStoreException e) {
            log.error("Error = Failed to read certificates | msg = {}, cause = {}", e.getMessage(), e.getCause());
            throw new RuntimeException("Error = reading truststore");
        }
    }

    public static boolean isCertificateEntry(KeyStore keyStore, String t) throws Exception {
        try {
            log.info("TrustStore status = filtering certs");
            return keyStore.isCertificateEntry(t);
        } catch (KeyStoreException e) {
            log.error("Error = Failed to read certificates | msg = {}, cause = {}", e.getMessage(), e.getCause());
            throw new RuntimeException("Error = reading truststore", e);
        }
    }

    private static KeyStore getKeyStore() throws ConfigurationException {
        try {
            File file = getFile("rds-combined-ca-bundle.pem");


            Certificate clientCertificate = loadCertificate(file);
//            PrivateKey privateKey = loadPrivateKey(privateKeyPem);
//            Certificate caCertificate = loadCertificate(caPem);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(CertificateLoader.class.getClassLoader().getResourceAsStream("cacerts.jks"), "changeit".toCharArray());
            //keyStore.load(null, null);
            //keyStore.setCertificateEntry("ca-cert", caCertificate);
            keyStore.setCertificateEntry("client-cert", clientCertificate);
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore);


            //keyStore.setKeyEntry("client-key", privateKey, TEMPORARY_KEY_PASSWORD.toCharArray(), new Certificate[]{clientCertificate});
            return keyStore;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static File getFile(String fileName) throws URISyntaxException {
        URL resource = CertificateLoader.class.getClassLoader().getResource(fileName);
        File file;
        if (resource == null) {
            throw new IllegalArgumentException("file not found! " );
        } else {

            // failed if files have whitespaces or special characters
            //return new File(resource.getFile());

            file =  new File(resource.toURI());
        }
        return file;
    }

    private static Certificate loadCertificate(File certificatePem) throws IOException, GeneralSecurityException {
        try (FileReader keyReader = new FileReader(certificatePem)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            final byte[] content = readPemContent(keyReader);
            return certificateFactory.generateCertificate(new ByteArrayInputStream(content));
        }
    }

//    private PrivateKey loadPrivateKey(String privateKeyPem) throws IOException, GeneralSecurityException {
//        return pemLoadPrivateKeyPkcs1OrPkcs8Encoded(privateKeyPem);
//    }

    private static byte[] readPemContent(FileReader pem) throws IOException {
        final byte[] content;
        try (PemReader pemReader = new PemReader(pem)) {
            final PemObject pemObject = pemReader.readPemObject();
            content = pemObject.getContent();
        }
        return content;
    }

//    private static PrivateKey pemLoadPrivateKeyPkcs1OrPkcs8Encoded(
//            String privateKeyPem) throws GeneralSecurityException, IOException {
//        // PKCS#8 format
//        final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
//        final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";
//
//        // PKCS#1 format
//        final String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
//        final String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";
//
//        if (privateKeyPem.contains(PEM_PRIVATE_START)) { // PKCS#8 format
//            privateKeyPem = privateKeyPem.replace(PEM_PRIVATE_START, "").replace(PEM_PRIVATE_END, "");
//            privateKeyPem = privateKeyPem.replaceAll("\\s", "");
//
//            byte[] pkcs8EncodedKey = Base64.getDecoder().decode(privateKeyPem);
//
//            KeyFactory factory = KeyFactory.getInstance("RSA");
//            return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));
//
//        } else if (privateKeyPem.contains(PEM_RSA_PRIVATE_START)) {  // PKCS#1 format
//
//            privateKeyPem = privateKeyPem.replace(PEM_RSA_PRIVATE_START, "").replace(PEM_RSA_PRIVATE_END, "");
//            privateKeyPem = privateKeyPem.replaceAll("\\s", "");
//
//            DerInputStream derReader = new DerInputStream(Base64.getDecoder().decode(privateKeyPem));
//
//            DerValue[] seq = derReader.getSequence(0);
//
//            if (seq.length < 9) {
//                throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
//            }
//
//            // skip version seq[0];
//            BigInteger modulus = seq[1].getBigInteger();
//            BigInteger publicExp = seq[2].getBigInteger();
//            BigInteger privateExp = seq[3].getBigInteger();
//            BigInteger prime1 = seq[4].getBigInteger();
//            BigInteger prime2 = seq[5].getBigInteger();
//            BigInteger exp1 = seq[6].getBigInteger();
//            BigInteger exp2 = seq[7].getBigInteger();
//            BigInteger crtCoef = seq[8].getBigInteger();
//
//            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2,
//                    exp1, exp2, crtCoef);
//
//            KeyFactory factory = KeyFactory.getInstance("RSA");
//
//            return factory.generatePrivate(keySpec);
//        }
//
//        throw new GeneralSecurityException("Not supported format of a private key");
//    }
}
