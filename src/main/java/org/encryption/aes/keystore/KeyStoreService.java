package org.encryption.aes.keystore;

import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Component
public class KeyStoreService {

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    @PostConstruct
    public void setUpKeyStore() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] keyStorePassword = "123abc".toCharArray();
        try {
            keyStore.load(null, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH+"keystore.jceks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }

    public KeyStore storeKeyInKeyStore(String aliasName, SecretKey secretKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] keyStorePassword = "123abc".toCharArray();
        try(FileInputStream keyStoreInputStream = new FileInputStream(KEY_STORE_PATH+"keystore.jceks")) {
            keyStore.load(keyStoreInputStream, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        char[] keyEntryPassword = "456def".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyEntryPassword);

        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        keyStore.setEntry(aliasName, secretKeyEntry, entryPassword);

        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH+"keystore.jceks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }

        return keyStore;
    }

}
