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

import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, RequestObjectValidatorImpl.class, KeyStoreManager.class})
public class RequestObjectValidatorImplTest extends PowerMockTestCase {
    private RSAPrivateKey rsaPrivateKey;

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test(expectedExceptions = RequestObjectException.class)
    public void validateRequestObjectTest() throws Exception {
        String requestObject = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KICJpc3MiOiA\n" +
                "    iczZCaGRSa3F0MyIsDQogImF1ZCI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmN\n" +
                "    vbSIsDQogInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsDQogImNsaWV\n" +
                "    udF9pZCI6ICJzNkJoZFJrcXQzIiwNCiAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8\n" +
                "    vY2xpZW50LmV4YW1wbGUub3JnL2NiIiwNCiAic2NvcGUiOiAib3BlbmlkIiwNCiA\n" +
                "    ic3RhdGUiOiAiYWYwaWZqc2xka2oiLA0KICJub25jZSI6ICJuLTBTNl9XekEyTWo\n" +
                "    iLA0KICJtYXhfYWdlIjogODY0MDAsDQogImNsYWltcyI6IA0KICB7DQogICAidXN\n" +
                "    lcmluZm8iOiANCiAgICB7DQogICAgICJnaXZlbl9uYW1lIjogeyJlc3NlbnRpYWw\n" +
                "    iOiB0cnVlfSwNCiAgICAgIm5pY2tuYW1lIjogbnVsbCwNCiAgICAgImVtYWlsIjo\n" +
                "    geyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgImVtYWlsX3ZlcmlmaWVkIjogeyJ\n" +
                "    lc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgInBpY3R1cmUiOiBudWxsDQogICAgfSw\n" +
                "    NCiAgICJpZF90b2tlbiI6IA0KICAgIHsNCiAgICAgImdlbmRlciI6IG51bGwsDQo\n" +
                "    gICAgICJiaXJ0aGRhdGUiOiB7ImVzc2VudGlhbCI6IHRydWV9LA0KICAgICAiYWN\n" +
                "    yIjogeyJ2YWx1ZXMiOiBbInVybjptYWNlOmluY29tbW9uOmlhcDpzaWx2ZXIiXX0\n" +
                "    NCiAgICB9DQogIH0NCn0.nwwnNsk1-ZkbmnvsF6zTHm8CHERFMGQPhos-EJcaH4H\n" +
                "    h-sMgk8ePrGhw_trPYs8KQxsn6R9Emo_wHwajyFKzuMXZFSZ3p6Mb8dkxtVyjoy2\n" +
                "    GIzvuJT_u7PkY2t8QU9hjBcHs68PkgjDVTrG1uRTx0GxFbuPbj96tVuj11pTnmFC\n" +
                "    UR6IEOXKYr7iGOCRB3btfJhM0_AKQUfqKnRlrRscc8Kol-cSLWoYE9l5QqholImz\n" +
                "    jT_cMnNIznW9E7CDyWXTsO70xnB4SkG6pXfLSjLLlxmPGiyon_-Te111V8uE83Il\n" +
                "    zCYIb_NMXvtTIVc1jpspnTSD7xMbpL-2QgwUsAlMGzw\n";
        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");
        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isJSON(requestObject)).thenReturn(false);

        mockStatic(RequestObjectValidatorImpl.class);
        PowerMockito.spy(RequestObjectValidatorImpl.class);
        Path clientStorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "resources",
                "security", "client-truststore.jks");
        Path configPath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository", "conf",
                "identity", "Endpointconfig.properties");

        PowerMockito.doReturn(configPath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
                "./repository/conf/identity/EndpointConfig.properties");
        PowerMockito.doReturn(clientStorePath.toString()).when(RequestObjectValidatorImpl.class, "buildFilePath",
                "./repository/resources/security/client-truststore.jks");
        requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        Assert.assertNotNull(requestObjectValidator.getPayload(), "Signature validation failed.");
    }

    @Test(expectedExceptions = RequestObjectException.class)
    public void DecryptTest() throws Exception {
        String requestObject = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.K52jFwAQJH-\n" +
                " DxMhtaq7sg5tMuot_mT5dm1DR_01wj6ZUQQhJFO02vPI44W5nDjC5C_v4p\n" +
                " W1UiJa3cwb5y2Rd9kSvb0ZxAqGX9c4Z4zouRU57729ML3V05UArUhck9Zv\n" +
                "ssfkDW1VclingL8LfagRUs2z95UkwhiZyaKpmrgqpKX8azQFGNLBvEjXnx\n" +
                "-xoDFZIYwHOno290HOpig3aUsDxhsioweiXbeLXxLeRsivaLwUWRUZfHRC\n" +
                " _HGAo8KSF4gQZmeJtRgai5mz6qgbVkg7jPQyZFtM5_ul0UKHE2y0AtWm8I\n" +
                "zDE_rbAV14OCRZJ6n38X5urVFFE5sdphdGsNlA.gjI_RIFWZXJwaO9R.oa\n" +
                "E5a-z0N1MW9FBkhKeKeFa5e7hxVXOuANZsNmBYYT8G_xlXkMD0nz4fIaGt\n" +
                "uWd3t9Xp-kufvvfD-xOnAs2SBX_Y1kYGPto4mibBjIrXQEjDsKyKwndxzr\n" +
                "utN9csmFwqWhx1sLHMpJkgsnfLTi9yWBPKH5Krx23IhoDGoSfqOquuhxn0\n" +
                "y0WkuqH1R3z-fluUs6sxx9qx6NFVS1NRQ-LVn9sWT5yx8m9AQ_ng8MBWz2\n" +
                "BfBTV0tjliV74ogNDikNXTAkD9rsWFV0IX4IpA.sOLijuVySaKI-FYUaBy\n" +
                "wpg";
        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        rsaPrivateKey = Mockito.mock(RSAPrivateKey.class);
        PrivateKey privateKey = mock(PrivateKey.class);
        KeyStoreManager keyStoreManagerMock = mock(KeyStoreManager.class);
        when(keyStoreManagerMock.getDefaultPrivateKey()).thenReturn(privateKey);
        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(-1234)).thenReturn(keyStoreManagerMock);
        mockStatic(RequestObjectValidatorImpl.class);
        when((RequestObjectValidatorImpl.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isJSON(requestObject)).thenReturn(false);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);


        requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        Assert.assertNotNull(requestObjectValidator.getPayload(), "Failed to decrypt the request object.");

    }
}
