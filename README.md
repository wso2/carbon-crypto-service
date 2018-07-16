# Carbon Crypto Service

Carbon Crypto Service is a configurable framework to cater crypto needs in Carbon products.
In a software all the crypto needs can be put in to two categories.

1) Handling data encryption for storing. i.e. internal crypto needs

2) Using cryptography when dealing with external parties. i.e. external crypto needs.

The Carbon Crypto Service provides an extensible way to cater these two categories.

## Concepts

1) Internal crypto provider

    The component which deals with data encryption and decryption for internal usage. e.g. storing

2) External crypto provider

    The component which deals with the signing, signature validation, encryption, decryption when working with external entities.

3) Crypto context

    One of the main purposes of the crypto service is to provide a developer friendly API to handle cryptography in Carbon product.
The crypto context helps the developers to write the context specific logic (e.g. Finding the public key of the external party for validating the signature) once is re-use it by just passing the context for operation.

    ```
    verifySignature(data, signature, algorithm, javaSecurityAPIProvider, cryptoContext);
    ```

4) Key resolver chain

    In external crypto scenarios the keys of the external entities (i.e. public keys) might be stored in different places. e.g. Databases, KeyStores. Key resolver chains find the applicable key information based on the crypto context.

 ## The default implementations

1) Default internal crypto provider

    The default internal crypto provider is based on asymmetric cryptography due to historical reasons. This implementation reads the needed Java KeyStore information from a configuration file. More details can be found in the **How to use** section.
    The crypto service ships a [symmetric key based internal crypto provider](https://github.com/wso2/carbon-crypto-service/blob/master/components/org.wso2.carbon.crypto.provider/src/main/java/org/wso2/carbon/crypto/provider/SymmetricKeyInternalCryptoProvider.java) as well. But it is not the default implementation.

2) Default external crypto provider

    The crypto service doesn't ship a default external crypto provider. The external crypto operations in Carbon products should deal with the complexity behind tenant key stores etc. which is outside the crypto service's scope.
    Therefore the Carbon Kernel ships an implementation to be used in Carbon products. For the sake of completeness that implementation also will be mentioned in this documentation whenever needed.

3) Default key resolver

    A context independent key resolver is shipped to be used as the last resort to resolve the needed key information for the given context. Since the key resolvers has a priority mechanism, if an applicable resolver is found for a context, the default resolver won't be used.

## How to use

1) Configure

    Below is the default configuration block for the crypto service. For the crypto service to work, a valid configuration block should be there in repository/conf/carbon.xml.

    ```
    <CryptoService>
      <Enabled>true</Enabled>
      <InternalCryptoProviderClassName>org.wso2.carbon.crypto.provider.KeyStoreBasedInternalCryptoProvider</InternalCryptoProviderClassName>
      <ExternalCryptoProviderClassName>org.wso2.carbon.core.encryption.KeyStoreBasedExternalCryptoProvider</ExternalCryptoProviderClassName>
      <KeyResolvers>
        <KeyResolver className="org.wso2.carbon.crypto.defaultProvider.resolver.ContextIndependentKeyResolver" priority="-1"/>
      </KeyResolvers>
    </CryptoService>

    <Security>
      <InternalKeyStore>
        <Location>path_of_the_key_store</Location>
        <Type>JKS</Type>
        <Password>password_of_the_key_store</Password>
        <KeyAlias>alias_of_the_key</KeyAlias>
        <KeyPassword>password_of_the_key</KeyPassword>
      </InternalKeyStore>
    </Security>
    ```

2) Invoke the API

    ```
    CryptoService cryptoService = // Get the implementation of the CryptoService using OSGi

    cryptoService.encrypt(plainTextBytes, algorithm, javaCryptoAPIProvider);

    ```

    All the available operations of the API are documented [here](https://github.com/wso2/carbon-crypto-service/blob/master/components/org.wso2.carbon.crypto.api/src/main/java/org/wso2/carbon/crypto/api/CryptoService.java).

## Extension points

1) Internal crypto provider

    Implement [InternalCryptoProvider](https://github.com/wso2/carbon-crypto-service/blob/master/components/org.wso2.carbon.crypto.api/src/main/java/org/wso2/carbon/crypto/api/InternalCryptoProvider.java)

2) External crypto provider

    Implement [ExternalCryptoProvider](https://github.com/wso2/carbon-crypto-service/blob/master/components/org.wso2.carbon.crypto.api/src/main/java/org/wso2/carbon/crypto/api/ExternalCryptoProvider.java)

3) Key resolver

    Implement [KeyResolver](https://github.com/wso2/carbon-crypto-service/blob/master/components/org.wso2.carbon.crypto.api/src/main/java/org/wso2/carbon/crypto/api/KeyResolver.java)


4) Crypto service

    Implement [CryptoService](https://github.com/wso2/carbon-crypto-service/blob/master/components/org.wso2.carbon.crypto.api/src/main/java/org/wso2/carbon/crypto/api/CryptoService.java)
