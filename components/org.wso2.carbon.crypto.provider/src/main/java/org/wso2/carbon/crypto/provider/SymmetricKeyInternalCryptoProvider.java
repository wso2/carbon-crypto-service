/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.crypto.provider;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CipherMetaDataHolder;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;
import org.wso2.carbon.uuid.generator.UUIDGeneratorManager;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The symmetric key implementation of {@link InternalCryptoProvider}
 */
public class SymmetricKeyInternalCryptoProvider implements InternalCryptoProvider {

    private static Log log = LogFactory.getLog(SymmetricKeyInternalCryptoProvider.class);
    private final byte[] secretKey;
    private final String keyId;
    private final byte[] oldSecretKey;
    private final boolean enableKeyId;
    private static final String DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM = "AES";
    private static final String AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM = "AES/GCM/NoPadding";
    private static final String DIGEST_ALGORITHM_SHA256 = "SHA-256";
    public static final int GCM_IV_LENGTH = 128;
    public static final int GCM_TAG_LENGTH = 128;

    public SymmetricKeyInternalCryptoProvider(String secretKey) {

        this(secretKey, secretKey, false);
    }

    public SymmetricKeyInternalCryptoProvider(String secretKey, String oldSecretKey, boolean enableKeyId) {

        byte[] decodedSecret = determineEncodingAndEncode(secretKey);
        this.secretKey = decodedSecret;
        this.keyId = hashSHA256(decodedSecret);
        this.oldSecretKey = determineEncodingAndEncode(oldSecretKey);
        this.enableKeyId = enableKeyId;
    }

    private static byte[] determineEncodingAndEncode(String secret) {

        // Use hex encoding if the secret is AES-256 (64 characters) or AES-192 (48 characters).
        if (secret.length() == 64 || secret.length() == 48) {
            try {
                return Hex.decodeHex(secret.toCharArray());
            } catch (DecoderException e) {
                throw new SecurityException(
                        "The provided string may contain invalid characters or be improperly formatted.");
            }
        }
        return secret.getBytes();
    }

    private static String hashSHA256(byte[] data) {

        try {
            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM_SHA256);
            return Base64.encode(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("Failed to compute hash due to an error." + e.getMessage());
        }
    }

    /**
     * Computes and returns the ciphertext of the given cleartext, using the underlying key store.
     *
     * @param cleartext               The cleartext to be encrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider
     * @return the ciphertext
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        try {
            Cipher cipher;
            if (StringUtils.isBlank(algorithm)) {
                algorithm = AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM;
            }
            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(algorithm);
            } else {
                cipher = Cipher.getInstance(algorithm, javaSecurityAPIProvider);
            }

            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());
            return cipher.doFinal(cleartext);
        } catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | NoSuchProviderException
                | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            String errorMessage = String.format("An error occurred while encrypting using the algorithm : '%s'"
                    , algorithm);

            // Log the exception from client libraries, to avoid missing information if callers code doesn't log it
            if(log.isDebugEnabled()){
                log.debug(errorMessage, e);
            }

            throw new CryptoException(errorMessage, e);
        }
    }

    /**
     * Computes and returns the cleartext of the given ciphertext.
     *
     * @param ciphertext              The ciphertext to be decrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider The Java Security Provider.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        return decrypt(ciphertext, algorithm, javaSecurityAPIProvider, (Object) null);
    }

    /**
     * Computes and returns the cleartext of the given ciphertext.
     *
     * @param ciphertext                The ciphertext to be decrypted.
     * @param algorithm                 The encryption / decryption algorithm
     * @param javaSecurityAPIProvider   The Java Security Provider.
     * @param params                    The parameters required for the decryption operation.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider, Object... params)
            throws CryptoException {

        boolean retry = false;
        try {
            SecretKeySpec secretKeySpec = getSecretKey();
            if (params != null && params.length > 0 && params[0] != null) {
                secretKeySpec = getSecretKey((String) params[0]);
                retry = true;
            }
            Cipher cipher;

            if (StringUtils.isBlank(algorithm)) {
                algorithm = AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM;
            }
            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(algorithm);
            } else {
                cipher = Cipher.getInstance(algorithm, javaSecurityAPIProvider);
            }
            if (AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM.equals(algorithm)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Decrypting internal data with '%s' algorithm.", algorithm));
                }
                CipherMetaDataHolder cipherMetaDataHolder = getCipherMetaDataHolderFromCipherText(ciphertext);
                // Use the old secret if keyID does not match.
                if (!retry && enableKeyId && !StringUtils.equals(keyId,cipherMetaDataHolder.getKeyId())) {
                    secretKeySpec = getOldSecretKey();
                }
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,
                        getGCMParameterSpec(cipherMetaDataHolder.getIvBase64Decoded()));
                if (cipherMetaDataHolder.getCipherBase64Decoded().length == 0) {
                    return StringUtils.EMPTY.getBytes();
                } else {
                    return cipher.doFinal(cipherMetaDataHolder.getCipherBase64Decoded());
                }

            } else {
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            }

            return cipher.doFinal(ciphertext);
        } catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | NoSuchProviderException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            String errorMessage = String.format("An error occurred while decrypting using the algorithm : '%s'"
                    , algorithm);

            // Log the exception from client libraries, to avoid missing information if callers code doesn't log it
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            if (e instanceof BadPaddingException && retry) {
                return decrypt(ciphertext, algorithm, javaSecurityAPIProvider);
            }

            throw new CryptoException(errorMessage, e);
        }
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider,
                          boolean returnSelfContainedCipherText) throws CryptoException {

        return encrypt(cleartext, algorithm, javaSecurityAPIProvider, returnSelfContainedCipherText, (Object) null);
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider,
                          boolean returnSelfContainedCipherText, Object... params) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Encrypting data with symmetric key encryption with algorithm: '%s'.", algorithm));
        }
        if (cleartext == null) {
            throw new CryptoException("Plaintext can't be null.");
        }
        if (AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM.equals(algorithm)) {
            return encryptWithGCMMode(cleartext, javaSecurityAPIProvider, returnSelfContainedCipherText, params);
        }
        return encryptWithoutGCMMode(cleartext, javaSecurityAPIProvider, returnSelfContainedCipherText, params);
    }

    private SecretKeySpec getSecretKey() {

        return new SecretKeySpec(secretKey, 0, secretKey.length, DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
    }

    private SecretKeySpec getOldSecretKey() {

        return new SecretKeySpec(oldSecretKey, 0, oldSecretKey.length, DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
    }

    /**
     * This method will get the secret key spec from the given custom secret key.
     * @param customSecretKey   custom secret key.
     * @return  secret key spec.
     */
    private SecretKeySpec getSecretKey(String customSecretKey) {

        byte[] encodedSecretKey = determineEncodingAndEncode(customSecretKey);
        return new SecretKeySpec(encodedSecretKey, 0, encodedSecretKey.length,
                DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
    }

    private byte[] getInitializationVector() {

        byte[] iv = new byte[GCM_IV_LENGTH];
        UUID timeBasedUUID = UUIDGeneratorManager.getTimeBasedUUIDGenerator().generate();
        ByteBuffer byteBuffer = ByteBuffer.wrap(iv);
        byteBuffer.putLong(timeBasedUUID.getMostSignificantBits());
        byteBuffer.putLong(timeBasedUUID.getLeastSignificantBits());
        return byteBuffer.array();
    }

    /**
     * This method will encrypt a given plain text in AES/GCM/NoPadding cipher transformation
     *
     * @param plaintext                     plain text that need to be encrypted in this mode.
     * @param javaSecurityAPIProvider       crypto provider
     * @param returnSelfContainedCipherText A boolean which denotes whether the cipher text should be in self
     *                                      contained  mode or not.
     * @return byte array of encrypted and self contained cipher text, which include cipher text and iv value.
     * @throws CryptoException
     */
    private byte[] encryptWithGCMMode(byte[] plaintext, String javaSecurityAPIProvider,
                                      boolean returnSelfContainedCipherText, Object... params)
            throws CryptoException {

        Cipher cipher;
        byte[] cipherText;
        if (!returnSelfContainedCipherText) {
            throw new CryptoException("Symmetric encryption with GCM mode only supports self contained cipher " +
                    "text generation.");

        }
        SecretKeySpec secretKeySpec = getSecretKey();
        if (params != null && params.length > 0 && params[0] != null) {
            secretKeySpec = getSecretKey((String) params[0]);
        }
        byte[] iv = getInitializationVector();
        try {
            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM);
            } else {
                cipher = Cipher.getInstance(AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM, javaSecurityAPIProvider);
            }
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, getGCMParameterSpec(iv));
            if (plaintext.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Plaintext is empty. An empty array will be used as the ciphertext bytes.");
                }
                cipherText = StringUtils.EMPTY.getBytes();
            } else {
                cipherText = cipher.doFinal(plaintext);
            }
            cipherText = createSelfContainedCiphertextWithGCMMode(cipherText, AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM, iv);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {

            String errorMessage = String.format("Error occurred while initializing and encrypting using Cipher object" +
                    " with algorithm: '%s'.", AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM);
            throw new CryptoException(errorMessage, e);
        }
        return cipherText;
    }

    /**
     * This method will encrypt a given plain text in AES/ECB/PKCS5Padding cipher transformation
     *
     * @param plaintext                     Plain text that need to be encrypted in this mode.
     * @param javaSecurityAPIProvider       Crypto provider.
     * @param returnSelfContainedCipherText Whether the ciphertext should be in self-contained  mode or not.
     * @return byte array of encrypted cipher text.
     * @throws CryptoException
     */
    private byte[] encryptWithoutGCMMode(byte[] plaintext, String javaSecurityAPIProvider,
                                      boolean returnSelfContainedCipherText, Object... params)
            throws CryptoException {

        Cipher cipher;
        SecretKeySpec secretKeySpec = getSecretKey();
        if (params != null && params.length > 0 && params[0] != null) {
            secretKeySpec = getSecretKey((String) params[0]);
        }
        try {
            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
            } else {
                cipher = Cipher.getInstance(DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM, javaSecurityAPIProvider);
            }
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            byte[] cipherText;
            if (plaintext.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Plaintext is empty. An empty array will be used as the ciphertext bytes.");
                }
                cipherText = StringUtils.EMPTY.getBytes();
                if (returnSelfContainedCipherText) {
                    return createSelfContainedCiphertextWithPlainAES(cipherText, DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
                } else {
                    return cipherText;
                }
            }
            cipherText = cipher.doFinal(plaintext);
            if (returnSelfContainedCipherText) {
                return createSelfContainedCiphertextWithPlainAES(cipherText, DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
            }
            return cipherText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                 NoSuchProviderException | IllegalBlockSizeException e) {

            String errorMessage = String.format("An error occurred while encrypting using the algorithm : '%s'"
                    , DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
            if(log.isDebugEnabled()){
                log.debug(errorMessage, e);
            }
            throw new CryptoException(errorMessage, e);
        }
    }

    /**
     * This method is to create GCMParameterSpec which is needed to encrypt and decrypt operation with AES-GCM
     * @param iv
     * @return
     */
    private GCMParameterSpec getGCMParameterSpec(byte[] iv) {

        //The GCM parameter authentication tag length we choose is 128.
        return new GCMParameterSpec(GCM_TAG_LENGTH, iv);
    }

    /**
     * This method will create a self contained cipher text byte which will contain the cipher text of the original
     * plain text along with the iv value and cipher transformation
     * @param originalCipher cipher text of the plain text
     * @param transformation cipher transformation
     * @param iv initialization vector
     * @return self contained byte array.
     * @throws NoSuchAlgorithmException
     */
    private byte[] createSelfContainedCiphertextWithGCMMode(byte[] originalCipher, String transformation, byte[] iv) {

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        CipherMetaDataHolder cipherHolder = new CipherMetaDataHolder();
        byte[] cipherText = enableKeyId
                ? cipherHolder.getSelfContainedCiphertextWithIv(originalCipher, iv, keyId)
                : cipherHolder.getSelfContainedCiphertextWithIv(originalCipher, iv);
        cipherHolder.setCipherText(Base64.encode(cipherText));
        cipherHolder.setTransformation(transformation);
        cipherHolder.setIv(Base64.encode(iv));
        String cipherWithMetadataStr = gson.toJson(cipherHolder);
        if (log.isDebugEnabled()) {
            log.debug("Cipher with meta data : " + cipherWithMetadataStr);
        }
        return cipherWithMetadataStr.getBytes(Charset.defaultCharset());
    }

    private byte[] createSelfContainedCiphertextWithPlainAES(byte[] originalCipher, String transformation) {

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        CipherMetaDataHolder cipherHolder = new CipherMetaDataHolder();
        cipherHolder.setCipherText(Base64.encode(originalCipher));
        cipherHolder.setTransformation(transformation);
        String cipherWithMetadataStr = gson.toJson(cipherHolder);
        if (log.isDebugEnabled()) {
            log.debug("Cipher with meta data: " + cipherWithMetadataStr);
        }
        return cipherWithMetadataStr.getBytes(Charset.defaultCharset());
    }

    /**
     * This method will return the CipherMetaDataHolder object containing original cipher text and initialization
     * vector.
     * This method is used when using AES-GCM mode encryption
     * @param cipherTextBytes cipher text which contains original ciphertext and iv value.
     * @return CipherMetaDataHolder object
     */
    private CipherMetaDataHolder getCipherMetaDataHolderFromCipherText(byte[] cipherTextBytes) {

        CipherMetaDataHolder cipherMetaDataHolder = new CipherMetaDataHolder();
        cipherMetaDataHolder.setIvAndOriginalCipherText(cipherTextBytes);
        return cipherMetaDataHolder;
    }

}
