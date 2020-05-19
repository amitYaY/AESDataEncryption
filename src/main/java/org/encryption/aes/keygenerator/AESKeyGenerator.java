package org.encryption.aes.keygenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class AESKeyGenerator {

    private static final int AES_KEY_SIZE = 256;

    private static SecretKey aesKey = null;

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        // Generating Key
        if (aesKey == null) {
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            aesKey = keygen.generateKey();
        }
        return aesKey;
    }

}
