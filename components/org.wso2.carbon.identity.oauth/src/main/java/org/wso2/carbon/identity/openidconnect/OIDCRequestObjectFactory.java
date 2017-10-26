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

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
//Todo this is used in oidc spec

/**
 * This factory class is used to invoke the related request object builder classes.
 */

public class OIDCRequestObjectFactory {

    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    private static final String CLIENT_ID = "client_id";
    private static final String RESPONSE_TYPE = "response_type";
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";
    private static final String REQUEST_URI_PARAM_VALUE_BUILDER = "request_uri_param_value_builder";

    /**
     * Fetch and invoke the matched request builder class based on the identity.xml configurations.
     *
     * @param oauthRequest authorization request
     * @throws RequestObjectException
     */
    public static void buildRequestObject(OAuthAuthzRequest oauthRequest, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException {
        /**
         * So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
         * parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
         * The values for these parameters MUST match those in the Request Object, if present
         */
        if (isRequestParameter(oauthRequest.getParam(REQUEST))) {
            getBuildRequestObject(REQUEST_PARAM_VALUE_BUILDER).buildRequestObject(oauthRequest.getParam(REQUEST),
                    oAuth2Parameters);
            validateClientIdAndResponseType(oauthRequest);
        } else if (isRequestUri(REQUEST_URI)) {
            getBuildRequestObject(REQUEST_URI_PARAM_VALUE_BUILDER).buildRequestObject(oauthRequest.getParam(REQUEST_URI)
                    , oAuth2Parameters);
        }
    }

    private static void validateClientIdAndResponseType(OAuthAuthzRequest oauthRequest) throws RequestObjectException {
        if (!oauthRequest.getParam(CLIENT_ID).equals(RequestObject.getInstance().getClientId()) ||
                !oauthRequest.getParam(RESPONSE_TYPE).equals(RequestObject.getInstance().getResponseType())) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Request Object and " +
                    "Authorization request contains unmatched client_id or response_type");
        }
    }

    private static RequestObjectBuilder getBuildRequestObject(String requestParamValueBuilder) {
        return OAuthServerConfiguration.getInstance().getRequestObjectBuilders().get(requestParamValueBuilder);
    }

    private static boolean isRequestUri(String param) {
        return StringUtils.isNotBlank(param);
    }

    private static boolean isRequestParameter(String param) {
        return StringUtils.isNotBlank(param);
    }
}
