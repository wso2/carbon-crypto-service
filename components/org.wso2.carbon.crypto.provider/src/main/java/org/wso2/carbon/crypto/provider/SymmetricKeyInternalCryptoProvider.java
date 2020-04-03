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
import org.apache.axiom.om.util.Base64;
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
    private String secretKey;
    private static final String DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM = "AES";
    private static final String AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH = 16;
    public static final int GCM_TAG_LENGTH = 128;

    public SymmetricKeyInternalCryptoProvider(String secretKey) {

        this.secretKey = secretKey;
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
                algorithm = DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM;
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
     * @param javaSecurityAPIProvider
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        try {
            Cipher cipher;

            if (StringUtils.isBlank(algorithm)) {
                algorithm = DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM;
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
                cipher.init(Cipher.DECRYPT_MODE, getSecretKey(),
                        getGCMParameterSpec(cipherMetaDataHolder.getIvBase64Decoded()));
                return cipher.doFinal(cipherMetaDataHolder.getCipherBase64Decoded());

            } else {
                cipher.init(Cipher.DECRYPT_MODE, getSecretKey());
            }

            return cipher.doFinal(ciphertext);
        } catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | NoSuchProviderException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            String errorMessage = String.format("An error occurred while decrypting using the algorithm : '%s'"
                    , algorithm);

            // Log the exception from client libraries, to avoid missing information if callers code doesn't log it
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }

            throw new CryptoException(errorMessage, e);
        }
    }

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider,
                          boolean returnSelfContainedCipherText) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Encrypting data with symmetric key encryption with algorithm: '%s'.", algorithm));
        }
        if (AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM.equals(algorithm)) {
            return encryptWithGCMMode(cleartext, javaSecurityAPIProvider);
        }
        return encrypt(cleartext, algorithm, javaSecurityAPIProvider);

    }

    private SecretKeySpec getSecretKey() {

        return new SecretKeySpec(secretKey.getBytes(), 0, secretKey.getBytes().length,
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
     * @param plaintext               plain text that need to be encrypted in this mode.
     * @param javaSecurityAPIProvider crypto provider
     * @return byte array of encrypted and self contained cipher text, which include cipher text and iv value.
     * @throws CryptoException
     */
    private byte[] encryptWithGCMMode(byte[] plaintext, String javaSecurityAPIProvider)
            throws CryptoException {

        Cipher cipher;
        byte[] cipherText;
        byte[] iv = getInitializationVector();
        try {
            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM);
            } else {
                cipher = Cipher.getInstance(AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM, javaSecurityAPIProvider);
            }
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), getGCMParameterSpec(iv));
            cipherText = cipher.doFinal(plaintext);
            cipherText = createSelfContainedCiphertext(cipherText, AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM, iv);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {

            String errorMessage = String.format("Error occurred while initializing and encrypting using Cipher object" +
                    " with algorithm: '%s'.", AES_GCM_SYMMETRIC_CRYPTO_ALGORITHM);
            throw new CryptoException(errorMessage, e);
        }
        return cipherText;
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
    private byte[] createSelfContainedCiphertext(byte[] originalCipher, String transformation, byte[] iv) {

        Gson gson = new Gson();
        CipherMetaDataHolder cipherHolder = new CipherMetaDataHolder();
        cipherHolder.setCipherText(Base64.encode(cipherHolder.getSelfContainedCiphertextWithIv(originalCipher, iv)));
        cipherHolder.setTransformation(transformation);
        cipherHolder.setIv(Base64.encode(iv));
        String cipherWithMetadataStr = gson.toJson(cipherHolder);
        if (log.isDebugEnabled()) {
            log.debug("Cipher with meta data : " + cipherWithMetadataStr);
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
