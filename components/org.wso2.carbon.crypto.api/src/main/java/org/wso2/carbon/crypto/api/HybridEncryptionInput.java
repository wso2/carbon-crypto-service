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
 * Data holder for hybrid encryption input.
 * This class keeps the data needs to be encrypted and
 * if any available authentication data related to symmetric encryption.
 */
public class HybridEncryptionInput {

    private byte[] plainData;
    private byte[] authData;

    /**
     * Constructor of {@link HybridEncryptionInput} which requires only plain data for hybrid encryption.
     *
     * @param plainData : Byte array of plain data that needs to be encrypted.
     */
    public HybridEncryptionInput(byte[] plainData) {

        this.plainData = plainData;
        this.authData = null;
    }

    /**
     * Constructor of {@link HybridEncryptionInput} which requires plain data and
     * authentication data for hybrid encryption.
     *
     * @param plainData : Byte array of plain data that needs to be encrypted.
     * @param authData  : Byte array of authentication data related to hybrid encryption.
     */
    public HybridEncryptionInput(byte[] plainData, byte[] authData) {

        this.authData = authData;
        this.plainData = plainData;
    }

    public byte[] getPlainData() {

        return plainData;
    }

    public byte[] getAuthData() {

        return authData;
    }
}
