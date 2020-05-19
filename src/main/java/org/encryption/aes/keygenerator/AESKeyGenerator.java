package org.encryption.aes.keygenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class AESKeyGenerator {

    private static final int AES_KEY_SIZE = 256;

    private static SecretKey aesKey = null;

    public static SecretKey generateAESKey() {
        File file = new File("secretketstore.txt");
        if (aesKey == null) {
            try (FileOutputStream fileOutputStream = new FileOutputStream(file);
                 ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
                 DataOutputStream dataOutputStream = new DataOutputStream(outputStream)) {
                // Generating Key
                KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
                keygen.init(AES_KEY_SIZE);
                aesKey = keygen.generateKey();
                outputStream.writeObject(aesKey);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        return aesKey;
    }

}
