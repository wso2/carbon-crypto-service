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

import org.apache.commons.lang.StringUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.wso2.carbon.crypto.api.ExternalCryptoProvider;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class KeyStoreBasedExternalCryptoProviderTest {

    public static final String KEY_STORE_FILE_NAME = "keystore.jks";
    public static final String KEY_STORE_PASSWORD = "keystore-password";
    public static final String KEY_ALIAS = "key-alias";
    public static final String KEY_PASSWORD = "key-password";
    ExternalCryptoProvider jksCryptoProvider;
    PublicKey publicKey;
    PrivateKey privateKey;
    private KeyStore keyStore;

    /**
     * This data provider provides an array of (signing algorithm, javaSecurityAPIProvider) combinations.
     *
     * @return
     */
    @DataProvider(name = "signingAlgorithms")
    public static Object[][] getSigningAlgorithms() {

        return new Object[][]{{"SHA256withRSA", null}, {"SHA1withRSA", null}};
    }

    /**
     * This data provider provides an array of encryption algorithms.
     *
     * @return
     */
    @DataProvider(name = "encryptionAlgorithms")
    public static Object[][] getEncryptionAlgorithms() {

        return new Object[][]{{"RSA"}};
    }

    @BeforeClass
    public void init() throws Exception {

        keyStore = getKeyStore();
        publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
        jksCryptoProvider = new KeyStoreBasedExternalCryptoProvider();
    }

    private KeyStore getKeyStore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(this.getClass().getResourceAsStream(File.separator + KEY_STORE_FILE_NAME),
                KEY_STORE_PASSWORD.toCharArray());
        return keyStore;
    }

    private boolean canVerifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey, String algorithm,
                                       String javaSecurityAPIProvider) throws Exception {

        Signature signature;

        if (StringUtils.isBlank(javaSecurityAPIProvider)) {
            signature = Signature.getInstance(algorithm);
        } else {
            signature = Signature.getInstance(algorithm, javaSecurityAPIProvider);
        }

        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

}
