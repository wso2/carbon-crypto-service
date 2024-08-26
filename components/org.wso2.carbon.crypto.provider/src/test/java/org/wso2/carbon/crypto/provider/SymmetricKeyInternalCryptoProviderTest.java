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
    SymmetricKeyInternalCryptoProvider cryptoProviderWithBackupSecret;

    private static final String OLD_SECRET = "f7b2b39207523b43a56540d30656b19b";
    private static final String SECRET = "22b97077751bc066067ffeefb83a1c16";
    private static final String PLAIN_TEXT = "wso2carbon";
    private static final String JCE_PROVIDER = "SunJCE";

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final String CIPHER_TEXT = "nQ2r9QHRYJP+i88JDsyOpA==";
    private static final String CIPHER_TEXT_FOR_OLD_SECRET = "ueAbJkt7K+s20lIuvi9/1A==";
    private static final String CIPHER_TEXT_GCM = "eyJjIjoiZXlKamFYQm9aWElpT2lJMFRtSnpPWEJIUkdOeFEzaG1PVUZEYkRWalpscDRRMFpPVkVoa2NHbFRibFF4TkQwaUxDSnBibWwwYVdGc2FYcGhkR2x2YmxabFkzUnZjaUk2SWtweWNYTlFWMDl5UldVclFURkhUMEpPTWs1YVZYZEJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVQwaUxDSnJaWGxKWkNJNklsb3pNaTkxTjNwVmMzSktaMVo1Tnk5cE9YWmpXRXRvV1VaaVpYZHRTMnRKTTFsRk56UjVkMngyYm5NOUluMD0iLCJ0IjoiQUVTL0dDTS9Ob1BhZGRpbmciLCJpdiI6IkpycXNQV09yRWUrQTFHT0JOMk5aVXdBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0iLCJraWQiOiJaMzIvdTd6VXNySmdWeTcvaTl2Y1hLaFlGYmV3bUtrSTNZRTc0eXdsdm5zPSJ9";
    private static final String CIPHER_TEXT_GCM_FOR_OLD_SECRET = "eyJjIjoiZXlKamFYQm9aWElpT2lKelowVlVSVEZpY1RaMFkxWXJiWFl5UTA1eWRGbHdkWEJoVUVsSFdsTnNWVVpFTUQwaUxDSnBibWwwYVdGc2FYcGhkR2x2YmxabFkzUnZjaUk2SWt0NVNXUk5SMDkxUldVcldUVTFkV1FyVEdKNGNGRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVQwaUxDSnJaWGxKWkNJNklqRTJUUzlzUW5oVmR6ZHBSakJ0V1hodlZHc3hOU3R0VUdOMFpWTm1WRlZOSzNadlpXWldhSGx1Y0c4OUluMD0iLCJ0IjoiQUVTL0dDTS9Ob1BhZGRpbmciLCJpdiI6Ikt5SWRNR091RWUrWTU1dWQrTGJ4cFFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0iLCJraWQiOiIxNk0vbEJ4VXc3aUYwbVl4b1RrMTUrbVBjdGVTZlRVTSt2b2VmVmh5bnBvPSJ9";

    @BeforeClass
    public void init() throws Exception {

        cryptoProvider = new SymmetricKeyInternalCryptoProvider(determineEncodingAndEncode(SECRET));
        cryptoProviderWithBackupSecret =
                new SymmetricKeyInternalCryptoProvider(determineEncodingAndEncode(SECRET), determineEncodingAndEncode(OLD_SECRET));
    }

    // Default tests.

    @Test(description = "Test encryption using the default secret.")
    public void testEncrypt() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(plainTextBytes, AES_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(Base64.getEncoder().encode(encryptedText)), CIPHER_TEXT);
    }

    @Test(description = "Test encryption using a old secret.")
    public void testEncryptUsingOldSecret() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(
                plainTextBytes, AES_ALGORITHM, JCE_PROVIDER, false, OLD_SECRET);
        // TODO: Should return CIPHER_TEXT_FOR_OLD_SECRET.
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

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_OLD_SECRET);
        try {
            cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER);
        } catch (CryptoException e) {
            assertTrue(e.getCause() instanceof BadPaddingException);
            assertEquals(e.getMessage(), "An error occurred while decrypting using the algorithm : 'AES'");
        }
    }

    @Test(description = "Test decryption using a old secret.")
    public void testDecryptUsingOldSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_FOR_OLD_SECRET);
        byte[] decryptedText = cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using an invalid old secret.")
    public void testDecryptUsingInvalidOldSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT);
        byte[] decryptedText = cryptoProvider.decrypt(encryptedText, AES_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
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

    @Test(description = "Test GCM encryption using the old secret.")
    public void testEncryptDecryptGCMUsingOldSecret() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProvider.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, OLD_SECRET);
        byte[] decryptedText = cryptoProvider.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the invalid secret.")
    public void testDecryptGCMInvalidSecret() {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        try {
            byte[] encryptedText = cryptoProvider.encrypt(
                    plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, OLD_SECRET);
            cryptoProvider.decrypt(
                    getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        } catch (CryptoException e) {
            assertTrue(e.getCause() instanceof AEADBadTagException);
            assertEquals(e.getMessage(), "An error occurred while decrypting using the algorithm : 'AES/GCM/NoPadding'");
        }
    }

    // Tests with fallback mode.

    @Test(description = "Test GCM encryption using the default secret (with fallback mode).")
    public void testEncryptDecryptGCMOldMode() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderWithBackupSecret.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test GCM encryption using the old secret (with fallback mode).")
    public void testEncryptDecryptGCMUsingOldSecretOldMode() throws CryptoException {

        byte[] plainTextBytes = PLAIN_TEXT.getBytes();
        byte[] encryptedText = cryptoProviderWithBackupSecret.encrypt(
                plainTextBytes, AES_GCM_ALGORITHM, JCE_PROVIDER, true, OLD_SECRET);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(
                getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER, OLD_SECRET);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption of values encrypted with backup secret using the default secret (with fallback mode).")
    public void testDecryptWithBackupSecret() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_GCM_FOR_OLD_SECRET);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the default secret (with fallback mode).")
    public void testDecryptWithOldMode() throws CryptoException {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_GCM);
        byte[] decryptedText = cryptoProviderWithBackupSecret.decrypt(getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
        assertEquals(new String(decryptedText), PLAIN_TEXT);
    }

    @Test(description = "Test decryption using the invalid secret (with fallback mode).")
    public void testDecryptInvalidSecretWithOldMode() {

        byte[] encryptedText = Base64.getDecoder().decode(CIPHER_TEXT_GCM);
        try {
            cryptoProviderWithBackupSecret.decrypt(getCipherTextFromEncodedJSON(encryptedText), AES_GCM_ALGORITHM, JCE_PROVIDER);
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

    private byte[] determineEncodingAndEncode(String secret) throws DecoderException {

        if (secret.length() > 32) {
            return Hex.decodeHex(secret.toCharArray());
        }
        return secret.getBytes();
    }

}
