package org.encryption.aes.controller;

import org.encryption.aes.keygenerator.AESKeyGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.util.Map;

@RestController
@RequestMapping("/app")
public class KeyGeneratorController {

    @Autowired
    private AESKeyGenerator aesKeyGenerator;

    @RequestMapping(value = "/secretkey", method = RequestMethod.GET)
    public SecretKey getSecretKey() {
        return aesKeyGenerator.getAESKey();
    }

    // Key Generation Strategy #1
    @RequestMapping(value = "/new/secretkey", method = RequestMethod.POST)
    public SecretKey generateSecretKey() {
        return aesKeyGenerator.generateAESKey();
    }

    // Key Generation Strategy #2 -> Step-1 Create First Active Key
    @RequestMapping(value = "/first/active/secretkey", method = RequestMethod.POST)
    public SecretKey generateFirstSecretKey() {
        return aesKeyGenerator.generateAESKeyWithTimestampSuffixAlias();
    }

    // Key Generation Strategy #2 -> Step-2 Rotate Active Key
    @RequestMapping(value = "/rotate/active/secretkey", method = RequestMethod.POST)
    public Map<String, SecretKey> rotateKeyInKeyStoreWithTimestampSuffix() {
        return aesKeyGenerator.rotateKeyInKeyStoreWithTimestampSuffix();
    }

}
