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

import java.util.HashMap;
import java.util.Map;

/**
 * The class which encapsulated information which is used to find out the correct keys for crypto operations.
 * The context will be interpreted by applicable {@link KeyResolver} implementations.
 */
public class CryptoContext {

    private int tenantId;
    private String tenantDomain;
    private String type;
    private String identifier;
    private String purpose;
    private Map<String, String> properties;

    /**
     * The constructor which accepts all the needed information to create a {@link CryptoContext}
     *
     * @param tenantId     ID of the tenant which the crypto operations are going to be performed on.
     * @param tenantDomain Name of the tenant which the crypto operations are going to be performed on.
     * @param type         A name which denotes the type of the context. e.g. SERVICE-PROVIDER
     * @param identifier   An identifier of the context if there is any. e.g. service provider id
     * @param purpose      The purpose of the crypto operations.
     * @param properties   An arbitrary map of context properties.
     */
    public CryptoContext(int tenantId, String tenantDomain, String type, String identifier, String purpose,
                         Map<String, String> properties) {

        this.tenantId = tenantId;
        this.tenantDomain = tenantDomain;
        this.type = type;
        this.identifier = identifier;
        this.purpose = purpose;
        this.properties = properties;

        if (this.properties == null) {
            this.properties = new HashMap<>();
        }
    }

    /**
     * Creates and returns a {@link CryptoContext} which has no attribute values other than the tenant information.
     * <p>
     * This is a convenience method to create a context with minimal information.
     *
     * @param tenantId
     * @param tenantDomain
     * @return
     */
    public static CryptoContext buildEmptyContext(int tenantId, String tenantDomain) {

        return new CryptoContext(tenantId, tenantDomain, null, null, null, null);
    }

    public int getTenantId() {

        return tenantId;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public String getType() {

        return type;
    }

    public String getIdentifier() {

        return identifier;
    }

    public String getPurpose() {

        return purpose;
    }

    /**
     * Adds the given context property value against the given property name.
     * These properties will be interpreted by the applicable {@link KeyResolver}
     *
     * @param propertyName  Name of the property
     * @param propertyValue Value of the property
     */
    public void addProperty(String propertyName, String propertyValue) {

        this.properties.put(propertyName, propertyValue);
    }

    /**
     * Returns the context property which has given property name.
     *
     * @param propertyName Property name
     * @return The context property which has the given name.
     */
    public String getProperty(String propertyName) {

        return properties.get(propertyName);
    }

    @Override
    public String toString() {

        return "CryptoContext{" +
                "tenantId=" + tenantId +
                ", tenantDomain='" + tenantDomain + '\'' +
                ", type='" + type + '\'' +
                ", identifier='" + identifier + '\'' +
                ", purpose='" + purpose + '\'' +
                '}';
    }
}
