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
 * A simple data holder class which is used to encapsulate discovery information about a private key.
 */
public class PrivateKeyInfo {

    private String keyAlias;
    private String keyPassword;

    public PrivateKeyInfo(String keyAlias, String keyPassword) {

        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
    }

    public String getKeyAlias() {

        return keyAlias;
    }

    public String getKeyPassword() {

        return keyPassword;
    }

    @Override
    public String toString() {

        return "PrivateKeyInfo{" +
                "keyAlias='" + keyAlias + '\'' +
                '}';
    }
}
