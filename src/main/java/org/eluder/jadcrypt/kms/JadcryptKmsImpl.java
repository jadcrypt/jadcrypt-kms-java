package org.eluder.jadcrypt.kms;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import org.eluder.jadcrypt.Encoding;
import org.eluder.jadcrypt.Presets;

import java.nio.ByteBuffer;
import java.util.Map;

public class JadcryptKmsImpl implements JadcryptKms {

    private final AWSKMS kms;
    private final Encoding encoding;

    public JadcryptKmsImpl() {
        this(new AWSKMSClient(), Encoding.HEX);
    }

    public JadcryptKmsImpl(AWSKMS kms, Encoding encoding) {
        this.kms = kms;
        this.encoding = encoding;
    }

    @Override
    public String encrypt(String plain, String keyId, Map<String, String> context) {
        return this.encoding.encode(encryptRaw(plain.getBytes(Presets.CHARSET), keyId, context));
    }

    @Override
    public byte[] encryptRaw(byte[] plain, String keyId, Map<String, String> context) {
        EncryptRequest request = new EncryptRequest().withPlaintext(ByteBuffer.wrap(plain))
                                                     .withKeyId(keyId)
                                                     .withEncryptionContext(context);
        EncryptResult result = this.kms.encrypt(request);
        return result.getCiphertextBlob().array();
    }

    @Override
    public String decrypt(String encrypted, Map<String, String> context) {
        return new String(decryptRaw(this.encoding.decode(encrypted), context), Presets.CHARSET);
    }

    @Override
    public byte[] decryptRaw(byte[] encrypted, Map<String, String> context) {
        DecryptRequest request = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(encrypted))
                                                     .withEncryptionContext(context);
        DecryptResult result = this.kms.decrypt(request);
        return result.getPlaintext().array();
    }
}
