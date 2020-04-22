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

package org.wso2.carbon.crypto.api;


/**
 * The service contract for internal crypto providers.
 * An internal crypto provider is used for crypto needs related to internal operations.
 * One example is encrypting sensitive tokens before persisting inside a data store.
 * A symmetric key based implementation which reads the secret from a file, is a sample implementation of this contract.
 * <p><b>
 * As per the design decisions, the contract should never be amended in a way that the secret keys are
 * returned to the caller.
 * </b></p>
 */
public interface InternalCryptoProvider {

    /**
     * Computes and returns the ciphertext of the given cleartext.
     *
     * @param cleartext               The cleartext to be encrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider
     * @return The ciphertext
     * @throws CryptoException If something unexpected happens during the encryption operation.
     */
    byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException;

    /**
     * Computes and returns the cleartext of the given ciphertext.
     *
     * @param ciphertext              The ciphertext to be decrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException;

    /**
     * Computes and returns the ciphertext of the given cleartext.
     *
     * @param cleartext                     The cleartext to be encrypted.
     * @param algorithm                     The encryption / decryption algorithm
     * @param javaSecurityAPIProvider       The Java Security API provider.
     * @param returnSelfContainedCipherText Whether cipher text need to be self contained.
     * @return The ciphertext
     * @throws CryptoException
     */
    default byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider,
                           boolean returnSelfContainedCipherText) throws CryptoException {

        String errorMessage = "Encryption with self contained cipher text is not supported by this implementation.";
        throw new CryptoException(errorMessage);
    }

    /**
     * Computes and returns the cipher text of the given clear text. In this method api we do not pass the encryption
     * algorithm from outside. The algorithm should be identified from internal provider level.
     *
     * @param cleartext                     The clear text to be encrypted.
     * @param javaSecurityAPIProvider       The Java Security API provider.
     * @param returnSelfContainedCipherText Whether cipher text need to be self contained.
     * @return The cipher text
     * @throws CryptoException
     */
    default byte[] encrypt(byte[] cleartext, String javaSecurityAPIProvider,
                           boolean returnSelfContainedCipherText) throws CryptoException {

        String errorMessage = "Encryption with self contained cipher text is not supported by this implementation.";
        throw new CryptoException(errorMessage);
    }

    /**
     * Computes and returns the clear text of the given cipher text. In this method api we do not pass the encryption
     * algorithm from outside. The algorithm should be identified from internal provider level.
     *
     * @param ciphertext              The encrypted text.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @return The clear text.
     * @throws CryptoException
     */
    default byte[] decrypt(byte[] ciphertext, String javaSecurityAPIProvider) throws CryptoException {

        String errorMessage = "This method is not supported by this implementation.";
        throw new CryptoException(errorMessage);
    }

    /**
     * This method is used to set the encryption algorithm for the particular provider.
     *
     * @param algorithm encryption algorithm.
     * @throws CryptoException
     */
    default void setInternalCryptoProviderAlgorithm(String algorithm) throws CryptoException {

        String errorMessage = "This method is not supported by this implementation.";
        throw new CryptoException(errorMessage);
    }
}
