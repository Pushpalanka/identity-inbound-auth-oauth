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

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.identity.openidconnect.model.Claim;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

/**
 * This class is used to build request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestParamRequestObjectBuilder implements RequestObjectBuilder {

    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String SCOPE = "scope";
    private static final String STATE = "state";
    private static final String NONCE = "nonce";
    private static final String ISS = "iss";
    private static final String AUD = "aud";
    private static final String RESPONSE_TYPE = "response_type";
    private static final String MAX_AGE = "max_age";
    private static String CLAIMS = "claims";
    private static final Base64 base64Url = new Base64(true);
    //To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or idtoken
    // or any custom member.
    private static Map<String, List<Claim>> claimsforClaimRequestor = new HashMap<>();
    private static Log log = LogFactory.getLog(RequestParamRequestObjectBuilder.class);

    /**
     * Builds request object which comes as the value of the request query parameter of OIDC authorization request
     *
     * @param requestObject request object
     * @throws RequestObjectException
     */
    @Override
    public void buildRequestObject(String requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {
        JSONParser parser = new JSONParser();
        try {
            OAuthServerConfiguration.getInstance().getRequestObjectValidator().validateRequestObject(requestObject,
                    oAuth2Parameters);
            if (StringUtils.isNotBlank(OAuthServerConfiguration.getInstance().getRequestObjectValidator().getPayload())) {
                requestObject = OAuthServerConfiguration.getInstance().getRequestObjectValidator().getPayload();
            }
            JSONObject jsonObjectRequestedClaims = (JSONObject) parser.parse(requestObject);
            //To process the simple objects which comes with the request parameter.
            processSimpleObjects(jsonObjectRequestedClaims);
            //To process the claim object which comes with the request parameter.
            processClaimObject(parser, jsonObjectRequestedClaims);

        } catch (ParseException e) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Error occured while " +
                    "processing the request parameter value json object.");
        }
    }

    private void processSimpleObjects(JSONObject jsonObjectRequestedClaims) {
        String[] arrRequestedScopes;
        if (jsonObjectRequestedClaims.get(CLIENT_ID) != null) {
            RequestObject.getInstance().setClientId(jsonObjectRequestedClaims.get(CLIENT_ID).toString());
        }
        if (jsonObjectRequestedClaims.get(REDIRECT_URI) != null) {
            RequestObject.getInstance().setRedirectUri(jsonObjectRequestedClaims.get(REDIRECT_URI).toString());
        }
        if (jsonObjectRequestedClaims.get(SCOPE) != null) {
            String requestObjectScopes = jsonObjectRequestedClaims.get(SCOPE).toString();
            if (requestObjectScopes.contains(" ")) {
                RequestObject.getInstance().setScopes(jsonObjectRequestedClaims.get(SCOPE).toString().split(" "));
            } else {
                arrRequestedScopes = new String[1];
                arrRequestedScopes[0] = requestObjectScopes;
                RequestObject.getInstance().setScopes(arrRequestedScopes);
            }
        }
        if (jsonObjectRequestedClaims.get(STATE) != null) {
            RequestObject.getInstance().setState(jsonObjectRequestedClaims.get(STATE).toString());
        }
        if (jsonObjectRequestedClaims.get(NONCE) != null) {
            RequestObject.getInstance().setNonce(jsonObjectRequestedClaims.get(NONCE).toString());
        }
        if (jsonObjectRequestedClaims.get(ISS) != null) {
            RequestObject.getInstance().setIss(jsonObjectRequestedClaims.get(ISS).toString());
        }
        if (jsonObjectRequestedClaims.get(AUD) != null) {
            RequestObject.getInstance().setAud(jsonObjectRequestedClaims.get(AUD).toString());
        }
        if (jsonObjectRequestedClaims.get(RESPONSE_TYPE) != null) {
            RequestObject.getInstance().setResponseType(jsonObjectRequestedClaims.get(RESPONSE_TYPE).toString());
        }
        if (jsonObjectRequestedClaims.get(MAX_AGE) != null) {
            RequestObject.getInstance().setMaxAge(jsonObjectRequestedClaims.get(MAX_AGE).toString());
        }
    }

    private void processClaimObject(JSONParser parser, JSONObject jsonObjectRequestedClaims) throws ParseException {
        if (jsonObjectRequestedClaims.get(CLAIMS) != null) {
            String allRequestedClaims = null;
            String claimAttributeValue = null;
            JSONObject jsonObjectClaim = (JSONObject) parser.parse(jsonObjectRequestedClaims.get(CLAIMS).
                    toString());
            //To iterate the claims json object to fetch the claim requestor and all requested claims.

            for (Map.Entry<String, Object> requesterClaimMap : jsonObjectClaim.entrySet()) {
                List<Claim> essentialClaimsRequestParam = new ArrayList();
                if (jsonObjectClaim.get(requesterClaimMap.getKey()) != null) {
                    allRequestedClaims = jsonObjectClaim.get(requesterClaimMap.getKey()).toString();
                }
                if (log.isDebugEnabled()) {
                    log.debug("The " + requesterClaimMap.getKey() + " requests " + allRequestedClaims + " set of claims.");
                }
                JSONObject jsonObjectAllRequestedClaims = (JSONObject) parser.parse(allRequestedClaims);

                //To iterate all requested claims object to fetch the claim attributes and values for the fetched claim
                // requestor.
                for (Map.Entry<String, Object> requestedClaims : jsonObjectAllRequestedClaims.entrySet()) {
                    JSONObject jsonObjectClaimAttributes = null;
                    if (jsonObjectAllRequestedClaims.get(requestedClaims.getKey()) != null) {
                        jsonObjectClaimAttributes = (JSONObject) parser.parse(jsonObjectAllRequestedClaims.get
                                (requestedClaims.getKey()).toString());
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("The attributes " + jsonObjectAllRequestedClaims + "for the requested claim: " +
                                requestedClaims.getKey());
                    }
                    //To maintaain a claim - claim attribute mapping.
                    addClaimAttributes(claimAttributeValue, essentialClaimsRequestParam, jsonObjectClaimAttributes,
                            requestedClaims.getKey());
                }
                claimsforClaimRequestor.put(requesterClaimMap.getKey(), essentialClaimsRequestParam);
            }
            RequestObject.getInstance().setClaimsforRequestParameter(claimsforClaimRequestor);
        }
    }

    private void addClaimAttributes(String claimAttributeValue, List<Claim> essentialClaimsRequestParam,
                                    JSONObject jsonObjectClaimAttributes, String claimName) {
        Claim claim = new Claim();
        claim.setName(claimName);
        if (jsonObjectClaimAttributes != null) {
            //To iterate claim attributes object to fetch the attribute key and value for the fetched
            // requested claim in the fetched claim requestor
            for (Map.Entry<String, Object> claimAttributes : jsonObjectClaimAttributes.entrySet()) {
                Map<String, String> claimAttributesMap = new HashMap<>();
                if (jsonObjectClaimAttributes.get(claimAttributes.getKey()) != null) {
                    claimAttributeValue = jsonObjectClaimAttributes.get(claimAttributes.getKey()).toString();
                }
                claimAttributesMap.put(claimAttributes.getKey(), claimAttributeValue);
                claim.setClaimAttributesMap(claimAttributesMap);
                essentialClaimsRequestParam.add(claim);
            }
        } else {
            claim.setClaimAttributesMap(null);
            essentialClaimsRequestParam.add(claim);
        }
    }
}

