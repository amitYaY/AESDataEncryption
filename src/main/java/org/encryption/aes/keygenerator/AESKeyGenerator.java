package org.encryption.aes.keygenerator;

import org.encryption.aes.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;

@Component
public class AESKeyGenerator {

    @Autowired
    private KeyStoreService keyStoreService;

    private static final int AES_KEY_SIZE = 256;

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    public SecretKey getAESKey() {
        File file = new File(KEY_STORE_PATH + "secretketstore.txt");
        SecretKey aesKey = null;
        //SecretKey aesKey2 = null;
        try (FileInputStream fileInputStream = new FileInputStream(file);
             ObjectInputStream inputStream = new ObjectInputStream(fileInputStream)) {
            aesKey = (SecretKey) inputStream.readObject();
            //aesKey2 = (SecretKey) inputStream.readObject();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return aesKey;
    }

    public SecretKey generateAESKey() {

        SecretKey aesKey = null;
        File file = new File(KEY_STORE_PATH + "secretketstore.txt");

        try (FileOutputStream fileOutputStream = new FileOutputStream(file);
             ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream)) {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            aesKey = keygen.generateKey();
            outputStream.writeObject(aesKey);

            keyStoreService.storeKeyInKeyStore("Key1", aesKey);

            //Generate Second Key
            aesKey = keygen.generateKey();
            outputStream.writeObject(aesKey);

            keyStoreService.storeKeyInKeyStore("Key2", aesKey);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return aesKey;
    }

}
