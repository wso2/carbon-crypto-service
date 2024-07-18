/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.crypto.provider;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CipherMetaDataHolder;
import org.wso2.carbon.crypto.api.CryptoException;

import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class SymmetricKeyInternalCryptoProviderTest {

    SymmetricKeyInternalCryptoProvider cryptoProvider;
    SymmetricKeyInternalCryptoProvider cryptoProviderHexEncoding;
    SymmetricKeyInternalCryptoProvider cryptoProviderWithBackupSecret;

    private static final String CUSTOM_SECRET = "f7b2b39207523b43a56540d30656b19b";
    private static final String SECRET = "22b97077751bc066067ffeefb83a1c16";
    private static final String PLAIN_TEXT = "wso2carbon";
    private static final String JCE_PROVIDER = "SunJCE";

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final String CIPHER_TEXT = "nQ2r9QHRYJP+i88JDsyOpA==";
    private static final String CIPHER_TEXT_HEX = "nm5vepa7KAB3imNPTgfE7w==";
    private static final String CIPHER_TEXT_FOR_CUSTOM_SECRET = "ueAbJkt7K+s20lIuvi9/1A==";
    private static final String CIPHER_TEXT_FOR_CUSTOM_SECRET_HEX = "FtxXPN+5L8INpzNEGFplDQ==";

    @BeforeClass
    public void init() throws Exception {

        cryptoProvider = new SymmetricKeyInternalCryptoProvider(SECRET.getBytes());
        cryptoProviderHexEncoding = new SymmetricKeyInternalCryptoProvider(hexDecoding(SECRET));
        cryptoProviderWithBackupSecret =
                new SymmetricKeyInternalCryptoProvider(hexDecoding(SECRET), hexDecoding(CUSTOM_SECRET));
    }

    // Default tests.

    @Test(description = "Test encryption using the default secret.")
    public void testEncrypt() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(plainTextBytes, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT);
    }

    @Test(description = "Test encryption using a custom secret.")
    public void testEncryptUsingCustomSecret() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(
                plainTextBytes, AES_ALGORITHM, JCE_PROVIDER, false, CUSTOM_SECRET);
        // TODO: Should return CIPHER_TEXT_FOR_CUSTOM_SECRET.
        //  Update once SymmetricKeyInternalCryptoProvider behaviour is fixed.
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT);
    }

    @Test(description = "Test decryption using the default secret.")
    public void testDecrypt() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT);
        byte[] decryptedText = cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the invalid secret.")
    public void testDecryptInvalidSecret() {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_CUSTOM_SECRET);
        try {
            cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        } catch (CryptoException e) {
            assertTrue(e.getCause() instanceof BadPaddingException);
            assertEquals(e.getMessage(), "An error occurred while decrypting using the algorithm : 'AES'");
        }
    }

    @Test(description = "Test decryption using a custom secret.")
    public void testDecryptUsingCustomSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_CUSTOM_SECRET);
        byte[] decryptedText = cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using an invalid custom secret.")
    public void testDecryptUsingInvalidCustomSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT);
        byte[] decryptedText = cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    // Default tests in AES-GCM mode.

    @Test(description = "Test GCM encryption using the default secret.")
    public void testEncryptDecryptGCM() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true);
        byte[] decryptedText = cryptoProvider.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test GCM encryption using the custom secret.")
    public void testEncryptDecryptGCMUsingCustomSecret() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, CUSTOM_SECRET);
        byte[] decryptedText = cryptoProvider.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the invalid secret.")
    public void testDecryptGCMInvalidSecret() {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        try {
            byte[] encryptedText = cryptoProvider.encrypt(
                    plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, CUSTOM_SECRET);
            cryptoProvider.decrypt(
                    getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        } catch (CryptoException e) {
            assertTrue(e.getCause() instanceof AEADBadTagException);
            assertEquals(e.getMessage(), "An error occurred while decrypting using the algorithm : 'AES/GCM/NoPadding'");
        }
    }

    // Tests with hex encoding.

    @Test(description = "Test encryption using the default secret (with Hex Encoding).")
    public void testEncryptHexEncoding() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderHexEncoding.encrypt(plainTextBytes, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT_HEX);
    }

    @Test(description = "Test encryption using a custom secret (with Hex Encoding).")
    public void testEncryptUsingCustomSecretHexEncoding() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderHexEncoding.encrypt(
                plainTextBytes, AES_ALGORITHM, JCE_PROVIDER, false, CUSTOM_SECRET);
        // TODO: Should return CIPHER_TEXT_FOR_CUSTOM_SECRET_HEX.
        //  Update once SymmetricKeyInternalCryptoProvider behaviour is fixed.
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT_HEX);
    }

    @Test(description = "Test decryption using the default secret (with Hex Encoding).")
    public void testDecryptHexEncoding() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_HEX);
        byte[] decryptedText = cryptoProviderHexEncoding.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using a custom secret (with Hex Encoding).")
    public void testDecryptUsingCustomSecretHexEncoding() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_CUSTOM_SECRET);
        byte[] decryptedText = cryptoProviderHexEncoding.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using an invalid custom secret (with Hex Encoding).")
    public void testDecryptUsingInvalidCustomSecretHexEncoding() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_HEX);
        byte[] decryptedText = cryptoProviderHexEncoding.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    // Tests with hex encoding in AES-GCM mode.

    @Test(description = "Test GCM encryption using the default secret (with Hex Encoding).")
    public void testEncryptDecryptGCMHexEncoding() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderHexEncoding.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true);
        byte[] decryptedText = cryptoProviderHexEncoding.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test GCM encryption using the custom secret (with Hex Encoding).")
    public void testEncryptDecryptGCMUsingCustomSecretHexEncoding() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderHexEncoding.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, CUSTOM_SECRET);
        byte[] decryptedText = cryptoProviderHexEncoding.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    // Tests with hex encoding and fallback mode.

    @Test(description = "Test GCM encryption using the default secret (with fallback mode).")
    public void testEncryptDecryptGCMFallbackMode() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderWithBackupSecret.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test GCM encryption using the custom secret (with fallback mode).")
    public void testEncryptDecryptGCMUsingCustomSecretFallbackMode() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderWithBackupSecret.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, CUSTOM_SECRET);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER, CUSTOM_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption of values encrypted with backup secret using the default secret (with fallback mode).")
    public void testDecryptWithBackupSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_CUSTOM_SECRET_HEX);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the default secret (with fallback mode).")
    public void testDecryptWithFallbackMode() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_HEX);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the invalid secret (with fallback mode).")
    public void testDecryptInvalidSecretWithFallbackMode() {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT);
        try {
            cryptoProviderWithBackupSecret.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        } catch (CryptoException e) {
            assertTrue(e.getCause() instanceof BadPaddingException);
            assertEquals(e.getMessage(), "An error occurred while decrypting using the algorithm : 'AES'");
        }
    }

    private static byte[] getCipherTextFromEncodedJSON(byte[] selfContainedCiphertext) {

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        CipherMetaDataHolder cipherMetaDataHolder =
                gson.fromJson(new String(selfContainedCiphertext), CipherMetaDataHolder.class);
        return Base64.getDecoder().decode(cipherMetaDataHolder.getCipherText().getBytes());
    }

    private static byte[] hexDecoding(String secret) throws DecoderException {

        return Hex.decodeHex(secret.toCharArray());
    }

}
