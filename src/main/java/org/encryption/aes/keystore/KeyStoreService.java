package org.encryption.aes.keystore;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Component
public class KeyStoreService {

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    public KeyStore setUpKeyStore(String aliasName, SecretKey secretKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] keyStorePassword = "123abc".toCharArray();
        try {
            keyStore.load(null, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        char[] keyEntryPassword = "456def".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyEntryPassword);

        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        keyStore.setEntry(aliasName, secretKeyEntry, entryPassword);

        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH+"keystore.jks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }

        return keyStore;
    }

}
