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

package org.wso2.carbon.identity.oauth2;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class DefaultRequestObjectValidator implements RequestObjectValidator {

    private static Log log = LogFactory.getLog(DefaultRequestObjectValidator.class);
    private static Properties prop;
    private static final Base64 base64Url = new Base64(true);
    private static JSONObject jsonHeaderObject;

    @Override
    public boolean isSignatureValid(String requestObject) {

        String[] jwtTokenValues = requestObject.split("\\.");
        String jwtAssertion = null;
        byte[] jwtSignature = null;
        if (jwtTokenValues.length > 0) {
            String value = new String(base64Url.decode(jwtTokenValues[0].getBytes()));
            if (log.isDebugEnabled()) {
                log.debug("JWT Header :" + value);
            }
            JSONParser parser = new JSONParser();
            try {
                jsonHeaderObject = (JSONObject) parser.parse(value);
            } catch (ParseException e) {
                log.error("The Json is invalid.");
            }
        }
        if (jwtTokenValues.length > 1) {

            String value = new String(base64Url.decode(jwtTokenValues[1].getBytes()));
            if (log.isDebugEnabled()) {
                log.debug("JWT Body: " + value);
            }
            jwtAssertion = jwtTokenValues[0] + "." + jwtTokenValues[1];
        }

        if (jwtTokenValues.length > 2) {
            jwtSignature = base64Url.decode(jwtTokenValues[2].getBytes());
        }
        String thumbPrint = null;
        String signatureAlgo = null;
        if (jsonHeaderObject.get("x5t") != null) {
            thumbPrint = new String(base64Url.decode(((String) jsonHeaderObject.get("x5t")).getBytes()));
        } else if (jsonHeaderObject.get("kid") != null) {
            thumbPrint = new String(base64Url.decode(((String) jsonHeaderObject.get("kid")).getBytes()));
        } else {
            return false;
        }
        if (jsonHeaderObject.get("alg") != null) {
            signatureAlgo = (String) jsonHeaderObject.get("alg");
        }
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

        if (jwtAssertion != null && jwtSignature != null) {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(new FileInputStream(buildFilePath(getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE))),
                        getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE_PASSWORD).toCharArray());
                String alias = getAliasForX509CertThumb(thumbPrint.getBytes(), keyStore);
                if (StringUtils.isEmpty(alias)) {
                    log.error("Could not obtain the alias from the certificate.");
                    return false;
                }
                Certificate certificate = keyStore.getCertificate(alias);
                Signature signature = Signature.getInstance(signatureAlgo);
                signature.initVerify(certificate);
                signature.update(jwtAssertion.getBytes());
                return signature.verify(jwtSignature);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                    InvalidKeyException | SignatureException e) {
                log.error("Signature verification failed.");
            }
        } else {
            log.error("Signature is null");
        }
        return false;
    }

    @Override
    public boolean isObjectValid(String Object) {
        return true;
    }

    @Override
    public boolean isRequestUriValid(String url) {
        return true;
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

    private static String getAliasForX509CertThumb(byte[] thumb, KeyStore keyStore) {

        Certificate cert;
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
            for (Enumeration e = keyStore.aliases(); e.hasMoreElements(); ) {
                String alias = (String) e.nextElement();
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
            log.error("Failed to extract alias from the cert thumb");
        }
        return null;
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
}
