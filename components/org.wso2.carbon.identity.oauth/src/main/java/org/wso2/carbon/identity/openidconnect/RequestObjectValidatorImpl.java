/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.Key;
import java.security.KeyStore;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestObjectValidatorImpl implements RequestObjectValidator {

    private static Log log = LogFactory.getLog(RequestObjectValidatorImpl.class);
    private static Properties prop;
    private static final Base64 base64Url = new Base64(true);
    String jwtAssertion;
    byte[] jwtSignature;
    String headerValue;
    private static String payload;
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        RequestObjectValidatorImpl.payload = payload;
    }

   ;private void processJwtToken(String[] jwtTokenValues) throws RequestObjectException {
        String bodyValue;
        if (jwtTokenValues.length > 0) {
            headerValue = new String(base64Url.decode(jwtTokenValues[0].getBytes()));
            if (log.isDebugEnabled()) {
                log.debug("JWT Header :" + headerValue);
            }
        }

        if (jwtTokenValues.length > 1) {
            bodyValue = new String(base64Url.decode(jwtTokenValues[1].getBytes()));
            if (log.isDebugEnabled()) {
                log.debug("JWT Body: " + bodyValue);
            }
            setPayload(bodyValue);
            jwtAssertion = jwtTokenValues[0] + "." + jwtTokenValues[1];
        }

        if (jwtTokenValues.length > 2) {
            jwtSignature = base64Url.decode(jwtTokenValues[2].getBytes());
        }
    }

    @Override
    public void validateSignature(String requestObject) throws RequestObjectException {
        String thumbPrint;
        String signatureAlgo = JWSAlgorithm.NONE.toString();
        String[] jwtTokenValues = requestObject.split("\\.");

        if (jwtTokenValues != null) {
            processJwtToken(jwtTokenValues);
        }

        if (getJsonHeaderObject() != null && getJsonHeaderObject().get("x5t") != null) {
            thumbPrint = getJsonHeaderObject().get("x5t").toString();
        } else if (getJsonHeaderObject() != null && getJsonHeaderObject().get("kid") != null) {
            thumbPrint = getJsonHeaderObject().get("kid").toString();
        } else {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Can not find the certificate" +
                    " thumbprint for signature validation");
        }
        if (log.isDebugEnabled()) {
            log.debug("The certificate thumbPrint value for the certificate is: " + thumbPrint);
        }

        if (getJsonHeaderObject().get("alg") != null) {
            signatureAlgo = (String) getJsonHeaderObject().get("alg");
        }
        signatureAlgo = getMappedSignatureAlgorithm(signatureAlgo);
        if (log.isDebugEnabled()) {
            log.debug("The signature algorithm used to sign the jwt is: " + signatureAlgo);
        }
        verifySignature(thumbPrint, signatureAlgo);
    }

    /**
     * Decrypt the request object.
     *
     * @param requestObject    requestObject
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public void decrypt(String requestObject, OAuth2Parameters oAuth2Parameters) throws RequestObjectException {
        EncryptedJWT encryptedJWT;
        try {
            encryptedJWT = EncryptedJWT.parse(requestObject);
            String tenantDomain = getTenantDomainForDecryption(oAuth2Parameters);
            int tenantId = OAuth2Util.getTenantId(tenantDomain);
            Key key = getPrivateKey(tenantDomain, tenantId);
            RSAPrivateKey rsaPrivateKey =(RSAPrivateKey)key;
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
            encryptedJWT.decrypt(decrypter);
            if (encryptedJWT != null && encryptedJWT.getCipherText() != null) {
                setPayload(encryptedJWT.getCipherText().toString());
            }
            //if the request object is a nested jwt then the payload of the jwe is a jws.
            if (encryptedJWT != null && encryptedJWT.getCipherText() != null && encryptedJWT.getCipherText().toString()
                    .split(".").length == 3) {
                validateSignature(encryptedJWT.getCipherText().toString());
                if (log.isDebugEnabled()) {
                    log.debug("As the request object is a nested jwt, passed the payload to validate the signature.");
                }
            }
        } catch (JOSEException | IdentityOAuth2Exception | java.text.ParseException e) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Failed to decrypt " +
                    "request object.");
        }
    }

    /**
     * Decide whether this request object is a signed object encrypted object or a nested object.
     *
     * @param requestObject    request object
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public void validateRequestObject(String requestObject, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException {
        if (!OAuth2Util.isJSON(requestObject)) {
            String[] jwtTokenValues = requestObject.split("\\.");
            if (jwtTokenValues.length == 3) {
                validateSignature(requestObject);
            } else if (jwtTokenValues.length == 5) {
                decrypt(requestObject, oAuth2Parameters);
            }
        }
    }

    /**
     * Get tenant domain from oAuth2Parameters.
     *
     * @param oAuth2Parameters oAuth2Parameters
     * @return Tenant domain
     */
    private String getTenantDomainForDecryption(OAuth2Parameters oAuth2Parameters) {
        return oAuth2Parameters.getTenantDomain();
    }

    private void verifySignature(String thumbPrint, String signatureAlgo) throws RequestObjectException {
        if (jwtAssertion != null && jwtSignature != null) {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(new FileInputStream(buildFilePath(getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE))),
                        getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE_PASSWORD).toCharArray());
                String alias = getAliasForX509CertThumb(thumbPrint.getBytes(), keyStore);

                if (StringUtils.isEmpty(alias)) {
                    log.error("Could not obtain the alias from the certificate.");
                    throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Could not obtain" +
                            " the alias from the certificate.");
                }

                isSignatureVerified(jwtAssertion, jwtSignature, signatureAlgo, keyStore, alias);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                    InvalidKeyException | SignatureException e) {
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, e.getMessage());
            }
        } else {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Signature is null.");
        }
    }

    private boolean isSignatureVerified(String jwtAssertion, byte[] jwtSignature, String signatureAlgo, KeyStore keyStore
            , String alias) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Certificate certificate = keyStore.getCertificate(alias);
        Signature signature = Signature.getInstance(signatureAlgo);
        signature.initVerify(certificate);
        signature.update(jwtAssertion.getBytes());
        return signature.verify(jwtSignature);
    }

    private JSONObject getJsonHeaderObject() throws RequestObjectException {

        JSONParser parser = new JSONParser();
        JSONObject jsonHeaderObject = null;
        try {
            jsonHeaderObject = (JSONObject) parser.parse(headerValue);
        } catch (ParseException e) {
            log.error("The Json is invalid.");
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "JWT json header is " +
                    "invalid.");
        }
        return jsonHeaderObject;
    }

    private String getMappedSignatureAlgorithm(String signatureAlgo) {
        if ("RS256".equals(signatureAlgo)) {
            signatureAlgo = "SHA256withRSA";
        } else if ("RS515".equals(signatureAlgo)) {
            signatureAlgo = "SHA512withRSA";
        } else if ("RS384".equals(signatureAlgo)) {
            signatureAlgo = "SHA384withRSA";
        } else {
            // by default
            signatureAlgo = "SHA256withRSA";
        }
        return signatureAlgo;
    }

    /**
     * Build the absolute path of a give file path
     *
     * @param path File path
     * @return Absolute file path
     */
    private static String buildFilePath(String path) {

        if (StringUtils.isNotEmpty(path) && path.startsWith(".")) {
            // Relative file path is given
            File currentDirectory = new File(new File(".")
                    .getAbsolutePath());
            try {
                path = currentDirectory.getCanonicalPath() + File.separator + path;
            } catch (IOException e) {
                log.error("Error occured while re·trieving current directory path");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("File path for TrustStore : " + path);
        }
        return path;
    }

    /**
     * Get property value by key
     *
     * @param key Property key
     * @return Property value
     */
    private static String getPropertyValue(String key) throws IOException {

        if (prop == null) {
            prop = new Properties();
            String configFilePath = buildFilePath(OAuthConstants.CONFIG_RELATIVE_PATH);
            File configFile = new File(configFilePath);
            InputStream inputStream = new FileInputStream(configFile);
            prop.load(inputStream);
        }
        return prop.getProperty(key);
    }

    private static String getAliasForX509CertThumb(byte[] thumb, KeyStore keyStore) throws RequestObjectException {
        Certificate cert;
        MessageDigest sha;
        String alias = null;
        try {
            sha = MessageDigest.getInstance("SHA-1");
            for (Enumeration e = keyStore.aliases(); e.hasMoreElements(); ) {
                alias = (String) e.nextElement();
                Certificate[] certs = keyStore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    cert = keyStore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                } else {
                    cert = certs[0];
                }
                sha.update(cert.getEncoded());
                byte[] data = sha.digest();
                if (new String(thumb).equals(hexify(data))) {
                    return alias;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Failed to extract alias" +
                    " from the cert thumb.");
        }
        return alias;
    }

    private static String hexify(byte bytes[]) {
        char[] hexDigits =
                {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
                        'e', 'f'};
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }

    public static Key getPrivateKey(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {
        Key privateKey;
        if (!(privateKeys.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain,
                        e);
            }
            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                // obtain private key
                privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

            } else {
                try {
                    privateKey = tenantKSM.getDefaultPrivateKey();
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error while obtaining private key for super tenant", e);
                }
            }
            //privateKey will not be null always
            privateKeys.put(tenantId, privateKey);
        } else {
            //privateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
            // does not allow to store null values
            privateKey = privateKeys.get(tenantId);
        }
        return privateKey;
    }

}
