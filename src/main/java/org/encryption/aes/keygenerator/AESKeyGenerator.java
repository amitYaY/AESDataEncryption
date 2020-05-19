package org.encryption.aes.keygenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;

public class AESKeyGenerator {

    private static final int AES_KEY_SIZE = 256;

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    public static SecretKey getAESKey() {
        File file = new File(KEY_STORE_PATH+"secretketstore.txt");
        SecretKey aesKey = null;

        try (FileInputStream fileInputStream = new FileInputStream(file);
             ObjectInputStream inputStream = new ObjectInputStream(fileInputStream)) {
            aesKey = (SecretKey) inputStream.readObject();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return aesKey;
    }

    public static SecretKey generateAESKey() {

        SecretKey aesKey = null;
        File file = new File(KEY_STORE_PATH+"secretketstore.txt");

        try (FileOutputStream fileOutputStream = new FileOutputStream(file);
             ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream)) {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            aesKey = keygen.generateKey();
            outputStream.writeObject(aesKey);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return aesKey;
    }

}
