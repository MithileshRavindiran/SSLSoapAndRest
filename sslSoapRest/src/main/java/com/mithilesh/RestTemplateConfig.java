package com.mithilesh;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by elisaveta on 20.2.18.
 */
@Configuration
public class RestTemplateConfig {

    @Autowired
    CardConfig cardConfig;

    //This needs a .p12 file
    @Bean
    public RestTemplate restTemplate() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, IOException, CertificateException {

        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(getSSLSocketFactory()).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return new RestTemplate(requestFactory);
    }

    private SSLContext loadClientCertificate() throws KeyManagementException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        return SSLContexts.custom().loadKeyMaterial(new File(cardConfig.getCertificates().getCertificateKey()), cardConfig.getCertificates().getPrivateKey().toCharArray(), cardConfig.getCertificates().getStoreKey().toCharArray()).build();
    }

    private SSLConnectionSocketFactory getSSLSocketFactory() throws KeyManagementException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        return new SSLConnectionSocketFactory(loadClientCertificate(),
                new String[]{"TLSv1.2"}, null, SSLConnectionSocketFactory.getDefaultHostnameVerifier());

       /* wsecu:
        visa:
        baseUri: ${VISA_URL:https://sandbox.api.visa.com/vctc/}
        resourcePath: ${VISA_RESOURCE_PATH:customerrules/v1/consumertransactioncontrols/{documentID}/rules}
            registerPath: ${VISA_REGISTER_PATH:customerrules/v1/consumertransactioncontrols}
            userId: ${VISA_USERID:NFE529XSF08DO6CEASRW21rkCXY35zKipk7EC0Hh9pOKM_uUk}
            password: ${VISA_PASSWORD:2z78FuP5Cid5}
            certificates:
            certificateKey: ${VISA_CERT_PATH:digital-banking-services\kubernetes\docker\certs\VISA_DPS_keyAndCertBundle.p12}
            privateKey: ${VISA_CERT_PRIVATE_KEY:backbase}
            storeKey: ${VISA_CERT_STORE_KEY:backbase}*/
    }

    /*
         * Create a RestTemplate bean, using the RestTemplateBuilder provided
         * by the auto-configuration.

         */ //This  uses a PFX fILE
    @Bean
    RestTemplate restTemplate() throws Exception {

        /*
         * Sample certs use the same password
         */
        char[] password = getFederalReserve().getPassword().toCharArray();

        /*
         * Create an SSLContext that uses client.jks as the client certificate
         * and the truststore.jks as the trust material (trusted CA certificates).
         * In this sample, truststore.jks contains ca.pem which was used to sign
         * both client.pfx and server.jks.
         */
        SSLContext sslContext = SSLContextBuilder
                .create()
                .loadKeyMaterial(loadPfx(getFederalReserve().getCertificateLocation(), password), password)
                .build();

        /*
         * Create an HttpClient that uses the custom SSLContext
         */
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();

        /*
         * Create a RestTemplate that uses a request factory that references
         * our custom HttpClient
         */
        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(client));
    }

    private KeyStore loadPfx(String file, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_INSTANCE);
        File key = ResourceUtils.getFile(file);
        try (InputStream in = new FileInputStream(key)) {
            keyStore.load(in, password);
        }
        return keyStore;
    }

    public RestTemplate au10tixrestTemplate() throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
        SSLContext sslContext = SSLContextBuilder
                .create()
                .loadKeyMaterial(ResourceUtils.getFile(keyStoreLocation),
                        keyStorePassword.toCharArray(), keyStorePassword.toCharArray())
                .loadTrustMaterial(ResourceUtils.getFile(trustStoreLocation), trustStorePassword.toCharArray())
                //.loadTrustMaterial(null, acceptingTrustStrategy)
                .build();
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();
        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(client);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        restTemplate.getMessageConverters().add(0, mappingJacksonHttpMessageConverter());
        return restTemplate;
    }
}
