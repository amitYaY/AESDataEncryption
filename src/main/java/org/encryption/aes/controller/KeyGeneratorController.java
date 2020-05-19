package org.encryption.aes.controller;

import org.encryption.aes.keygenerator.AESKeyGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;

@RestController
@RequestMapping("/app")
public class KeyGeneratorController {

    @Autowired
    private AESKeyGenerator aesKeyGenerator;

    @RequestMapping(value = "/secretkey", method = RequestMethod.GET)
    public SecretKey getSecretKey() {
        return aesKeyGenerator.getAESKey();
    }

    @RequestMapping(value = "/new/secretkey", method = RequestMethod.POST)
    public SecretKey generateSecretKey() {
        return aesKeyGenerator.generateAESKey();
    }

}
