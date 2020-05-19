package org.encryption.aes;

import org.encryption.aes.keygenerator.AESKeyGenerator;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;

@RestController
@RequestMapping("/app")
public class KeyGeneratorController {

    @RequestMapping(value = "/secretkey", method = RequestMethod.GET)
    public SecretKey getSecretKey() {
        return AESKeyGenerator.generateAESKey();
    }

}
