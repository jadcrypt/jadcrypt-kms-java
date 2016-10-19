package org.eluder.jadcrypt.kms;

import java.util.Map;

public interface JadcryptKms {

    String encrypt(String plain, String keyId, Map<String, String> context);

    byte[] encryptRaw(byte[] plain, String keyId, Map<String, String> context);

    String decrypt(String encrypted, Map<String, String> context);

    byte[] decryptRaw(byte[] encrypted, Map<String, String> context);
}
