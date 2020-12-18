package org.encryption.aes.keystore;

import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Enumeration;

@Component
public class KeyStoreService {

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    private static final String ACTIVE_KEY_ALISA_PREFIX = "active";

    private static final String BACKUP_KEY_ALISA_PREFIX = "backup";

    private static final String ENCRYPTION_KEY_DELIMITER = "#timestamp#";

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

    @PostConstruct
    public void setUpKeyStoreForStrategyWithSuffix() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] keyStorePassword = "123abc".toCharArray();
        try {
            keyStore.load(null, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH+"keystoreWithPrefixAlias.jceks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }

    // Strategy #1
    public KeyStore storeKeyInKeyStore(String aliasName, SecretKey secretKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        char[] keyStorePassword = "storePass".toCharArray();
        try (FileInputStream keyStoreInputStream = new FileInputStream(KEY_STORE_PATH + "keystore.jceks")) {
            keyStore.load(keyStoreInputStream, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        char[] keyEntryPassword = "keyPass".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyEntryPassword);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(aliasName, secretKeyEntry, entryPassword);

        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH + "keystore.jceks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }
        return keyStore;
    }

    // Strategy #2-> Step-1
    public KeyStore storeNewKeyInKeyStoreWithTimestampSuffix(LocalDateTime keyGenerationTime, SecretKey secretKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        char[] keyStorePassword = "storePass".toCharArray();
        try (FileInputStream keyStoreInputStream = new FileInputStream(KEY_STORE_PATH + "keystoreWithPrefixAlias.jceks")) {
            keyStore.load(keyStoreInputStream, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        char[] keyEntryPassword = "keyPass".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyEntryPassword);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(ACTIVE_KEY_ALISA_PREFIX + ENCRYPTION_KEY_DELIMITER + keyGenerationTime.toEpochSecond(ZoneOffset.UTC), secretKeyEntry, entryPassword);
        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH + "keystoreWithPrefixAlias.jceks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }
        return keyStore;
    }

    // Strategy #2-> Step-2
    public KeyStore rotateKeyInKeyStoreWithTimestampSuffix(LocalDateTime keyGenerationTime, SecretKey newSecretKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] keyStorePassword = "storePass".toCharArray();
        try (FileInputStream keyStoreInputStream = new FileInputStream(KEY_STORE_PATH + "keystoreWithPrefixAlias.jceks")) {
            keyStore.load(keyStoreInputStream, keyStorePassword);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        char[] keyPassword = "keyPass".toCharArray();
        String backupAliasName = getBackupKeyAliasName(keyStore);
        if (backupAliasName != null) {
            keyStore.deleteEntry(backupAliasName);
        }
        String aliasName = getActiveKeyAliasName(keyStore);
        SecretKey backUpSecretKey = (SecretKey) keyStore.getKey(aliasName, keyPassword);
        String backUpSecretKeyTimestamp = aliasName.split(ENCRYPTION_KEY_DELIMITER)[1];
        String backUpSecretKeyAliasName = BACKUP_KEY_ALISA_PREFIX + ENCRYPTION_KEY_DELIMITER + backUpSecretKeyTimestamp;

        char[] keyEntryPassword = "keyPass".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyEntryPassword);
        KeyStore.SecretKeyEntry backUpSecretKeyEntry = new KeyStore.SecretKeyEntry(backUpSecretKey);
        keyStore.setEntry(backUpSecretKeyAliasName, backUpSecretKeyEntry, entryPassword);

        KeyStore.SecretKeyEntry activeSecretKeyEntry = new KeyStore.SecretKeyEntry(newSecretKey);
        String activeSecretKeyAliasName = ACTIVE_KEY_ALISA_PREFIX + ENCRYPTION_KEY_DELIMITER + keyGenerationTime.toEpochSecond(ZoneOffset.UTC);
        keyStore.setEntry(activeSecretKeyAliasName, activeSecretKeyEntry, entryPassword);

        keyStore.deleteEntry(aliasName);

        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(KEY_STORE_PATH + "keystoreWithPrefixAlias.jceks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }

        return keyStore;
    }

    private String getActiveKeyAliasName(KeyStore keyStore) throws KeyStoreException {

        String aliasName = null;
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String tempAlias = aliases.nextElement();
            if (tempAlias.startsWith(ACTIVE_KEY_ALISA_PREFIX)) {
                aliasName = tempAlias;
                break;
            }
        }
        return aliasName;
    }

    private String getBackupKeyAliasName(KeyStore keyStore) throws KeyStoreException {

        String aliasName = null;
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String tempAlias = aliases.nextElement();
            if (tempAlias.startsWith(BACKUP_KEY_ALISA_PREFIX)) {
                aliasName = tempAlias;
                break;
            }
        }
        return aliasName;
    }

}
