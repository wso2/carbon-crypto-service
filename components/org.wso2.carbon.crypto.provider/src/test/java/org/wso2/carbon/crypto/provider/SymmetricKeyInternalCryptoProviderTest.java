package org.wso2.carbon.crypto.provider;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CipherMetaDataHolder;
import org.wso2.carbon.crypto.api.CryptoException;

import java.util.Base64;

import static org.testng.Assert.assertEquals;

public class SymmetricKeyInternalCryptoProviderTest {

    SymmetricKeyInternalCryptoProvider symmetricKeyInternalCryptoProvider;
    private static final String OLD_SECRET = "f7b2b39207523b43a56540d30656b19b";
    private static final String SECRET = "22b97077751bc066067ffeefb83a1c16";
    private static final String PLAIN_TEXT = "wso2carbon";
    private static final String JCE_PROVIDER = "SunJCE";

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final String CIPHER_TEXT = "nQ2r9QHRYJP+i88JDsyOpA==";
    private static final String CIPHER_TEXT_FOR_OLD_SECRET = "ueAbJkt7K+s20lIuvi9/1A==";

    @BeforeClass
    public void init() throws Exception {

        symmetricKeyInternalCryptoProvider = new SymmetricKeyInternalCryptoProvider(SECRET);
    }

    @Test(description = "Test encryption using the default secret.")
    public void testEncrypt() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = symmetricKeyInternalCryptoProvider.encrypt(
                plainTextBytes, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT);
    }

    @Test(description = "Test encryption using a custom secret.")
    public void testEncryptUsingCustomSecret() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = symmetricKeyInternalCryptoProvider.encrypt(
                plainTextBytes, AES_ALGORITHM, JCE_PROVIDER, false, OLD_SECRET);
        // TODO: should return CIPHER_TEXT_FOR_OLD_SECRET
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT);
    }

    @Test(description = "Test decryption using the default secret.")
    public void testDecrypt() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT);
        byte[] decryptedText = symmetricKeyInternalCryptoProvider.decrypt(
                encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using a custom secret.")
    public void testDecryptUsingCustomSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_OLD_SECRET);
        byte[] decryptedText = symmetricKeyInternalCryptoProvider.decrypt(
                encryptedText, AES_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using an invalid custom secret.")
    public void testDecryptUsingInvalidCustomSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT);
        byte[] decryptedText = symmetricKeyInternalCryptoProvider.decrypt(
                encryptedText, AES_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    // AES-GCM mode

    @Test(description = "Test GCM encryption using the default secret.")
    public void testEncryptDecryptGCM() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = symmetricKeyInternalCryptoProvider.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true);
        byte[] decryptedText = symmetricKeyInternalCryptoProvider.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test GCM encryption using the custom secret.")
    public void testEncryptDecryptGCMUsingCustomSecret() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = symmetricKeyInternalCryptoProvider.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, OLD_SECRET);
        byte[] decryptedText = symmetricKeyInternalCryptoProvider.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    private static byte[] getCipherTextFromEncodedJSON(byte[] selfContainedCiphertext) {

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        CipherMetaDataHolder cipherMetaDataHolder =
                gson.fromJson(new String(selfContainedCiphertext), CipherMetaDataHolder.class);
        return Base64.getDecoder().decode(cipherMetaDataHolder.getCipherText().getBytes());
    }

}
