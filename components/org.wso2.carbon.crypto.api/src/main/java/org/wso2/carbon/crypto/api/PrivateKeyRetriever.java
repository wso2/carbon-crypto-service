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

import java.security.PrivateKey;

/**
 * The service contract of an implementation of a private key retriever.
 * <p>
 * <b>Important:</b> Using this interface is discouraged. It was introduced to deal with situations where
 * third party libraries (e.g. opensaml) expects a private for crypto operations rather than letting another component
 * to do the operation for them.
 * </p>
 * <p>
 * If the need of a private key can be avoided, <b>do NOT</b> use this interface. Use {@link CryptoService} instead.
 * </p>
 */
public interface PrivateKeyRetriever {

    PrivateKey getPrivateKey(CryptoContext cryptoContext) throws CryptoException;

}
