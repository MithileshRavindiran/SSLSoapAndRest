GENERAL

1. Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy must be downloaded and installed
   in both ${java.home}/jre/lib/security/ and ${jdk.root}/jre/lib/security/.

2. Keystore file keystore.jks should be provided to the application. Client certificate should be added to
   the keystore. Use Portecle or execute following command (if keystore.jks does not exist it will be
   created):

     keytool -importkeystore -deststorepass <KeyStorePassword> -destkeypass <KeyStorePassword> -destkeystore keystore.jks -srckeystore <PFX file> -srcstoretype PKCS12 -alias 1 -destalias Au10tixBosClient

3. Provided trustsstore cacerts.jks contains needed root CA (self-signed on AU10TIX trial servers) certificate.
   The password of the cacerts.jks is changeit.

4. Run with following VM options:

    -Djavax.net.ssl.keyStore=keystore.jks
    -Djavax.net.ssl.keyStorePassword=<KeyStorePassword>
    -Djavax.net.ssl.trustStore=cacerts.jks
    -Djavax.net.ssl.trustStorePassword=changeit

// Same can be used for the SSL Soap connection and also to the Https Connection on the VM options
    -Djavax.net.ssl.keyStore=/Users/mravindran/IdeaProjects/au10tix/keystore.jks
    -Djavax.net.ssl.keyStorePassword=changeit
    -Djavax.net.ssl.trustStore=/Users/mravindran/IdeaProjects/au10tix/cacerts.jks
    -Djavax.net.ssl.trustStorePassword=changeit

5. For tracing SOAP, uncomment <cxf:logging/> in src/main/resources/cxf.xml

6. For testing with curl, use following command:

    curl -F "imageFile=@<Image file path>" --header "Content-type: multipart/mixed" http://localhost:9010/upload

curl -F "imageFile=@/Users/mravindran/fxcm/API-Docs/AU10TIX/AU10TIX BOS API - Au10tix BOS 6.55.0.6 - 18.11.2018/Help/Samples/REST/Test Images/IdentityDocument_Page0.jpg" --header "Content-type: multipart/mixed" http://localhost:9010/upload

7. For changing base URL of BOS service, change property bosBaseAddress in application.yml
