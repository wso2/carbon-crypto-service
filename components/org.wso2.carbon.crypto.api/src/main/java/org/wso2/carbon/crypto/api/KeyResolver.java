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
 * The service contract of an implementation of a key resolver.
 * <p>
 * Key resolvers are used to find the discovery information of keys / certificate, based on the given context.
 */
public abstract class KeyResolver {

    private int priority;

    /**
     * Returns the resolver priority.
     *
     * @return The resolver priority.
     */
    public int getPriority() {

        return priority;
    }

    /**
     * Sets the resolver priority.
     *
     * @param priority The resolver priority.
     */
    public void setPriority(int priority) {

        this.priority = priority;
    }

    /**
     * Checks whether this resolver is applicable for the given context.
     *
     * @param cryptoContext The context information
     * @return true if the resolver is applicable, false otherwise.
     */
    public abstract boolean isApplicable(CryptoContext cryptoContext);

    /**
     * Returns the discovery information about a private key, based on the given context.
     *
     * @param cryptoContext The context information.
     * @return The discovery information about the private key.
     */
    public abstract PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext);

    /**
     * Returns the discovery information about a certificate, based on the given context.
     *
     * @param cryptoContext The context information.
     * @return The discovery information about the certificate.
     */
    public abstract CertificateInfo getCertificateInfo(CryptoContext cryptoContext);

    @Override
    public String toString() {

        return String.format("%s{priority=%d}", this.getClass().getCanonicalName(), this.priority);
    }
}
