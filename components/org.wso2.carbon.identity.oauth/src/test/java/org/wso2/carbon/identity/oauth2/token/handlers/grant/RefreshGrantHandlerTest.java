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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

/**
 * Test class for RefreshGrantHandler test cases.
 */
@PrepareForTest({OAuthServerConfiguration.class, TokenMgtDAO.class, IdentityUtil.class, OAuth2Util.class,
        AbstractAuthorizationGrantHandler.class})
public class RefreshGrantHandlerTest extends PowerMockTestCase {

    @Mock
    private TokenMgtDAO mockTokenMgtDAO;
    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    private RefreshGrantHandler refreshGrantHandler;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        mockStatic(OAuthServerConfiguration.class);
        mockStatic(IdentityUtil.class);

        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(mockTokenMgtDAO);

        OauthTokenIssuer oauthTokenIssuer = spy(new OauthTokenIssuer() {

            @Override
            public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
                return null;
            }

            @Override
            public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
                return null;
            }

            @Override
            public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
                return null;
            }

            @Override
            public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
                return null;
            }

            @Override
            public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
                return null;
            }
        });

        when(mockOAuthServerConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthTokenIssuer);
        when(oauthTokenIssuer.accessToken(any(OAuthTokenReqMessageContext.class))).thenReturn("accessToken1");
        when(oauthTokenIssuer.refreshToken(any(OAuthTokenReqMessageContext.class))).thenReturn("refreshToken1");
    }

    @Test(dataProvider = "GetTokenIssuerDataForError")
    public void testIssue(Long validityPeriod, Boolean isValidToken, Boolean
            isRenew, Boolean checkUserNameAssertionEnabled, Boolean checkAccessTokenPartitioningEnabled, Boolean
                                  isUsernameCaseSensitive) throws Exception {
        mockStatic(OAuth2Util.class);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(checkUserNameAssertionEnabled);
        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(checkAccessTokenPartitioningEnabled);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("username");
        RefreshTokenValidationDataDO validationDataDO =
                constructValidationDataDO("accessToken1", TOKEN_STATE_EXPIRED, isUsernameCaseSensitive);
        when(mockTokenMgtDAO.validateRefreshToken(anyString(), anyString())).thenReturn(validationDataDO);
        doNothing().when(mockTokenMgtDAO)
                .invalidateAndCreateNewToken(anyString(), anyString(), anyString(), anyString(),
                        any(AccessTokenDO.class), anyString());

        if (isValidToken) {
            when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenReturn(new Long(5000));
        } else {
            when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenReturn(Long.valueOf(0));
        }
        when(mockOAuthServerConfiguration.isRefreshTokenRenewalEnabled()).thenReturn(isRenew);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(isUsernameCaseSensitive);

        System.setProperty(CarbonBaseConstants.CARBON_HOME, "");
        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId("clientId1");
        tokenReqDTO.setRefreshToken("refreshToken1");

        RefreshTokenValidationDataDO oldAccessToken = new RefreshTokenValidationDataDO();
        oldAccessToken.setTokenId("tokenId");
        oldAccessToken.setAccessToken("oldAccessToken");

        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.addProperty("previousAccessToken", oldAccessToken);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUser);
        tokenReqMessageContext.setValidityPeriod(validityPeriod);

        OAuth2AccessTokenRespDTO actual = refreshGrantHandler.issue(tokenReqMessageContext);
        assertEquals(actual.getErrorCode(), OAuthError.TokenResponse.INVALID_GRANT, "Should receive " +
                    "error response for invalid refresh token.");
    }

    @DataProvider(name = "GetTokenIssuerDataForError")
    public Object[][] tokenIssuerDataForError() {
        return new Object[][]{
                { UNASSIGNED_VALIDITY_PERIOD, false, true, true, false, false},
                { UNASSIGNED_VALIDITY_PERIOD, false, true, false, true, false},
                { UNASSIGNED_VALIDITY_PERIOD, false, false, true, false, false}
        };
    }

    private RefreshTokenValidationDataDO constructValidationDataDO(String accessToken, String refreshTokenState,
                                                                   Boolean isUsernameCaseSensitive) {
        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        validationDataDO.setAccessToken(accessToken);
        validationDataDO.setRefreshTokenState(refreshTokenState);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        if (isUsernameCaseSensitive) {
            authenticatedUser.setUserName("UserName");
            authenticatedUser.setAuthenticatedSubjectIdentifier("PRIMARY/UserName");
        } else {
            authenticatedUser.setUserName("username");
            authenticatedUser.setAuthenticatedSubjectIdentifier("PRIMARY/username");
        }
        authenticatedUser.setFederatedUser(true);
        validationDataDO.setAuthorizedUser(authenticatedUser);
        validationDataDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        validationDataDO.setValidityPeriodInMillis(10000);
        return validationDataDO;
    }
}
