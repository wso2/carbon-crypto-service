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

import java.security.cert.Certificate;

/**
 * A simple data holder class which is used to encapsulate either the {@link Certificate} or
 * the certificate information which can be used to retrieve the certificate.
 * <p>
 * <p>
 * {@link KeyResolver} implementations return {@link CertificateInfo} based on the given {@link CryptoContext},
 * and {@link ExternalCryptoProvider} implementations use it for certificate retrieval.
 * </p>
 */
public class CertificateInfo {

    private String certificateAlias;
    private Certificate certificate;

    public CertificateInfo(String certificateAlias, Certificate certificate) {

        this.certificateAlias = certificateAlias;
        this.certificate = certificate;
    }

    public String getCertificateAlias() {

        return certificateAlias;
    }

    public Certificate getCertificate() {

        return certificate;
    }

    @Override
    public String toString() {

        return "CertificateInfo{" +
                "certificateAlias='" + certificateAlias + '\'' +
                ", certificate=" + certificate +
                '}';
    }
}
