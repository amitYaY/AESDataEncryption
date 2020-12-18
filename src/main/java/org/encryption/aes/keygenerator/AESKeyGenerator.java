package org.encryption.aes.keygenerator;

import org.encryption.aes.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Component
public class AESKeyGenerator {

    @Autowired
    private KeyStoreService keyStoreService;

    private static final int AES_KEY_SIZE = 256; // To Use 256 size of AES Key need to update JCE Extended Policy

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    public SecretKey getAESKey() {
        File file = new File(KEY_STORE_PATH + "secretketstore.txt");
        SecretKey aesKey = null;
        try (FileInputStream fileInputStream = new FileInputStream(file);
             ObjectInputStream inputStream = new ObjectInputStream(fileInputStream)) {
            aesKey = (SecretKey) inputStream.readObject();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return aesKey;
    }

    // KeyGeneration Strategy  #1: Create new key every time.
    public SecretKey generateAESKey() {

        SecretKey aesKey = null;
        File file = new File(KEY_STORE_PATH + "secretketstore.txt");

        try (FileOutputStream fileOutputStream = new FileOutputStream(file);
             ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream)) {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(AES_KEY_SIZE);
            aesKey = keygen.generateKey();
            outputStream.writeObject(aesKey);
            keyStoreService.storeKeyInKeyStore("Key1", aesKey);
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        return aesKey;
    }

    // KeyGeneration Strategy  #2 -> Step-1: Create First Active Key with Key Alias Prefix ACTIVE and add Timestamp while KeyAlias Creation
    public SecretKey generateAESKeyWithTimestampSuffixAlias() {

        SecretKey aesKey = null;
        try {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            aesKey = keygen.generateKey();
            keyStoreService.storeNewKeyInKeyStoreWithTimestampSuffix(LocalDateTime.now(), aesKey);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return aesKey;
    }

    // KeyGeneration Strategy  #2 -> Step-2: Rotate Active Key. Now current Active will become Backup key
    public Map<String, SecretKey> rotateKeyInKeyStoreWithTimestampSuffix() {

        Map<String, SecretKey> secretKeyMap = new HashMap<>();

        try {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            SecretKey aesKey = keygen.generateKey();
            KeyStore keyStore = keyStoreService.rotateKeyInKeyStoreWithTimestampSuffix(LocalDateTime.now(), aesKey);

            Enumeration<String> aliases = keyStore.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                char[] keyPassword = "456def".toCharArray();
                secretKeyMap.put(alias, (SecretKey) keyStore.getKey(alias, keyPassword));
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return secretKeyMap;
    }
}
