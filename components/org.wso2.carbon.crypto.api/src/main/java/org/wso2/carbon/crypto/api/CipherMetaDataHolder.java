/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.crypto.api;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.axiom.om.util.Base64;

import java.nio.charset.Charset;

/**
 * This the POJO class to hold metadata of the cipher.
 */
public class CipherMetaDataHolder {

    // Base64 encoded ciphertext.
    private String c;

    // Transformation used for encryption, default is "RSA".
    private String t = "RSA";

    // Thumbprint of the certificate.
    private String tp;

    // Digest used to generate certificate thumbprint.
    private String tpd;

    // Initialization vector used in AES-GCM mode.
    private String iv;


    public String getTransformation() {
        return t;
    }

    public void setTransformation(String transformation) {
        this.t = transformation;
    }

    public String getCipherText() {
        return c;
    }

    public byte[] getCipherBase64Decoded() {
        return Base64.decode(c);
    }

    public void setCipherText(String cipher) {
        this.c = cipher;
    }

    public String getThumbPrint() {
        return tp;
    }

    public void setThumbPrint(String tp) {
        this.tp = tp;
    }

    public String getThumbprintDigest() {
        return tpd;
    }

    public void setThumbprintDigest(String digest) {
        this.tpd = digest;
    }

    /**
     * Method to return the initialization vector in AES/GCM/NoPadding transformation.
     *
     * @return initialization vector value in String format.
     */
    public String getIv() {

        return iv;
    }

    /**
     * Method to set the initialization vector in AES/GCM/NoPadding transformation.
     *
     * @param iv initialization vector value in String format
     */
    public void setIv(String iv) {

        this.iv = iv;
    }

    /**
     * Method to return initialization vector as a byte array
     *
     * @return byte array
     */
    public byte[] getIvBase64Decoded() {

        return Base64.decode(iv);
    }

    /**
     * Function to base64 encode ciphertext and set ciphertext
     * @param cipher
     */
    public void setCipherBase64Encoded(byte[] cipher) {
        this.c = Base64.encode(cipher);
    }

    /**
     * Function to set thumbprint
     * @param tp thumb print
     * @param digest digest (hash algorithm) used for to create thumb print
     */
    public void setThumbPrint(String tp, String digest) {
        this.tp = tp;
        this.tpd = digest;
    }

    public byte[] getSelfContainedCiphertextWithIv(byte[] originalCipher, byte[] iv) {

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();;
        CipherInitializationVectorHolder cipherInitializationVectorHolder = new CipherInitializationVectorHolder();
        cipherInitializationVectorHolder.setCipher(Base64.encode(originalCipher));
        cipherInitializationVectorHolder.setInitializationVector(Base64.encode(iv));
        String cipherWithMetadataStr = gson.toJson(cipherInitializationVectorHolder);

        return cipherWithMetadataStr.getBytes(Charset.defaultCharset());
    }

    /**
     * This method will extract the initialization vector and original ciphertext from input ciphertext and set them
     * to metadata in CipherMetaDataHolder object.
     *
     * @param cipherTextBytes This input cipher text contains both original cipher and iv.
     */
    public void setIvAndOriginalCipherText(byte[] cipherTextBytes) {

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();;
        String cipherStr = new String(cipherTextBytes, Charset.defaultCharset());
        CipherInitializationVectorHolder cipherInitializationVectorHolder =
                gson.fromJson(cipherStr, CipherInitializationVectorHolder.class);
        setIv(cipherInitializationVectorHolder.getInitializationVector());
        setCipherText(cipherInitializationVectorHolder.getCipher());
    }

    @Override
    public String toString() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }

    private class CipherInitializationVectorHolder{

        private String cipher;

        private String initializationVector;

        public String getCipher() {

            return cipher;
        }

        public void setCipher(String cipher) {

            this.cipher = cipher;
        }

        public String getInitializationVector() {

            return initializationVector;
        }

        public void setInitializationVector(String initializationVector) {

            this.initializationVector = initializationVector;
        }

    }
}

