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

import java.security.spec.AlgorithmParameterSpec;

/**
 * Class to store data related to hybrid encryption/decryption.
 * This contains encrypted symmetric key used for encryption and
 * ciphered data with any parameter specification related to symmetric encryption.
 */
public class HybridEncryptionOutput {

    private byte[] encryptedSymmetricKey;
    private byte[] cipherData;
    private AlgorithmParameterSpec parameterSpec;
    private byte[] authData;
    private byte[] authTag;

    /**
     * Constructor of Hybrid encryption output data holder.
     *
     * @param cipherData            : Byte array of encrypted data.
     * @param encryptedSymmetricKey : Byte array of encrypted symmetric key.
     */
    public HybridEncryptionOutput(byte[] cipherData, byte[] encryptedSymmetricKey) {

        this.cipherData = cipherData;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.parameterSpec = null;
        this.authData = null;
        this.authTag = null;
    }

    /**
     * Constructor of Hybrid encryption output data holder.
     *
     * @param cipherData            : Byte array of encrypted data.
     * @param encryptedSymmetricKey : Byte array of encrypted symmetric key.
     * @param parameterSpec         : Parameter specification used for symmetric encryption.
     */
    public HybridEncryptionOutput(byte[] cipherData, byte[] encryptedSymmetricKey,
                                  AlgorithmParameterSpec parameterSpec) {

        this.cipherData = cipherData;
        this.parameterSpec = parameterSpec;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.authTag = null;
        this.authData = null;
    }

    /**
     * Constructor of Hybrid encryption output data holder.
     *
     * @param cipherData            : Byte array of encrypted data.
     * @param encryptedSymmetricKey : Byte array of encrypted symmetric key.
     * @param parameterSpec         : Parameter specification used for symmetric encryption.
     * @param authData              : Byte array of authentication data used for symmetric encryption.
     * @param authTag               : Byte array of authentication tag produced by the symmetric encryption.
     */
    public HybridEncryptionOutput(byte[] cipherData, byte[] encryptedSymmetricKey, byte[] authData, byte authTag[],
                                  AlgorithmParameterSpec parameterSpec) {

        this.cipherData = cipherData;
        this.parameterSpec = parameterSpec;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.authData = authData;
        this.authTag = authTag;
    }

    public byte[] getEncryptedSymmetricKey() {

        return encryptedSymmetricKey;
    }

    public byte[] getCipherData() {

        return cipherData;
    }

    public AlgorithmParameterSpec getParameterSpec() {

        return parameterSpec;
    }

    public byte[] getAuthData() {

        return authData;
    }

    public byte[] getAuthTag() {

        return authTag;
    }
}
