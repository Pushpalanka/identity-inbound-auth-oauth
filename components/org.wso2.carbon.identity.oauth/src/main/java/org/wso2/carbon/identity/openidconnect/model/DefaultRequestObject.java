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
package org.wso2.carbon.identity.openidconnect.model;

import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * This class is used to model the request object which comes as a parameter of the OIDC authorization request
 */
public class DefaultRequestObject implements RequestObject {

    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String SCOPE = "scope";
    private static final String STATE = "state";
    private static final String NONCE = "nonce";
    private static final String ISS = "iss";
    private static final String AUD = "aud";
    private static final String RESPONSE_TYPE = "response_type";
    private static final String MAX_AGE = "max_age";
    private static String clientId;
    private static String redirectUri;
    private static String[] scopes;
    private static String state;
    private static String nonce;
    private static String iss;
    private static String aud;
    private static String responseType;
    private static String maxAge;
    private static boolean isSignatureValid = true;
    private static boolean isValidJson = true;
    private static boolean isValidRequestURI = true;
    //This iss used for extensions
    private Map<String, Object> properties = new HashMap<String, Object>();
    //To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or id token
    // or any custom member.
    private static Map<String, List<Claim>> claimsforRequestParameter = new HashMap<>();
    private static String CLAIMS = "claims";
    private static Log log = LogFactory.getLog(DefaultRequestObject.class);

    public DefaultRequestObject(String requestObject){
        processRequestObject(requestObject);
    }

    /**
     * This method for processing the json object which comes as a value of the request query parameter of the
     * authorization request in OIDC
     * @param requestObject
     */
    public void processRequestObject(String requestObject) {

        JSONParser parser = new JSONParser();
        try {
            if (!OAuth2Util.isJSON(requestObject)) {
                if (log.isDebugEnabled()) {
                    log.debug("Considering the request object as an encoded one as it is not a valid json. ");
                }
                if (OAuthServerConfiguration.getInstance().getRequestObjectValidator().isSignatureValid(requestObject) &&
                        OAuthServerConfiguration.getInstance().getRequestObjectValidator().isObjectValid(requestObject)) {
                    SignedJWT signedJWT = getSignedJWT(requestObject);
                    if (signedJWT != null && signedJWT.getPayload() != null) {
                        requestObject = new String(Base64.decodeBase64(getSignedJWT(requestObject).getPayload().toString().
                                getBytes(Charsets.UTF_8)), Charsets.UTF_8);
                    }
                } else {
                    setIsSignatureValid(false);
                }
            }
            if(!OAuth2Util.isJSON(requestObject)){
                setIsJson(false);
            }
            JSONObject jsonObjectRequestedClaims = (JSONObject) parser.parse(requestObject);
            processSimpleObjects(jsonObjectRequestedClaims);
            processClaimObject(parser, jsonObjectRequestedClaims);

        } catch (ParseException e) {
            log.error("Error ocuured while parsing the json object.");
        }
    }

    private void processClaimObject(JSONParser parser, JSONObject jsonObjectRequestedClaims) throws ParseException {

        if (jsonObjectRequestedClaims.get(CLAIMS) != null) {
            String allRequestedClaims = null;
            String claimAttributeValue = null;
            JSONObject jsonObjectClaimRequestors = (JSONObject) parser.parse(jsonObjectRequestedClaims.get(CLAIMS).toString());
            //To iterate the claims json object to fetch the claim requestor and all requested claims.
            for (String claimRequestor : jsonObjectClaimRequestors.keySet()) {
                ArrayList<Claim> essentialClaimsRequestParam = new ArrayList();
                if (jsonObjectClaimRequestors.get(claimRequestor) != null) {
                    allRequestedClaims = jsonObjectClaimRequestors.get(claimRequestor).toString();
                }
                if (log.isDebugEnabled()) {
                    log.debug("The " + claimRequestor + " requests " + allRequestedClaims + " set of claims.");
                }
                JSONObject jsonObjectAllRequestedClaims = (JSONObject) parser.parse(allRequestedClaims);
                //To iterate all requested claims object to fetch the claim attributes and values for the fetched claim
                // requestor.
                for (String requestedClaim : jsonObjectAllRequestedClaims.keySet()) {
                    JSONObject jsonObjectClaimAttributes = null;
                    if (jsonObjectAllRequestedClaims.get(requestedClaim) != null) {
                        jsonObjectClaimAttributes = (JSONObject) parser.parse(jsonObjectAllRequestedClaims.get
                                (requestedClaim).toString());
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("The attributes " + jsonObjectAllRequestedClaims + "for the requested claim: " +
                                requestedClaim);
                    }
                    Claim claim = new Claim();
                    claim.setName(requestedClaim);
                    if (jsonObjectClaimAttributes != null) {
                        //To iterate claim attributes object to fetch the attribute key and value for the fetched
                        // requested claim in the fetched claim requestor
                        for (String claimAttribute : jsonObjectClaimAttributes.keySet()) {
                            Map<String, String> claimAttributesMap = new HashMap<>();
                            if (jsonObjectClaimAttributes.get(claimAttribute) != null) {
                                claimAttributeValue = jsonObjectClaimAttributes.get(claimAttribute).toString();
                            }
                            claimAttributesMap.put(claimAttribute, claimAttributeValue);
                            claim.setClaimAttributesMap(claimAttributesMap);
                            essentialClaimsRequestParam.add(claim);
                        }
                    } else {
                        claim.setClaimAttributesMap(null);
                        essentialClaimsRequestParam.add(claim);
                    }
                }
                claimsforRequestParameter.put(claimRequestor, essentialClaimsRequestParam);
            }
            setClaimsforRequestParameter(claimsforRequestParameter);
        }
    }

    private void processSimpleObjects(JSONObject jsonObjectRequestedClaims) {
        String[] arrRequestedScopes = null;
        if (jsonObjectRequestedClaims.get(CLIENT_ID) != null) {
            setClientId(jsonObjectRequestedClaims.get(CLIENT_ID).toString());
        }
        if (jsonObjectRequestedClaims.get(REDIRECT_URI) != null) {
            setRedirectUri(jsonObjectRequestedClaims.get(REDIRECT_URI).toString());
        }
        if (jsonObjectRequestedClaims.get(SCOPE) != null) {
            String requestObjectScopes = jsonObjectRequestedClaims.get(SCOPE).toString();
            if (requestObjectScopes.contains(" ")) {
                setScopes(jsonObjectRequestedClaims.get(SCOPE).toString().split(" "));
            } else {
                arrRequestedScopes = new String[1];
                arrRequestedScopes[0] = requestObjectScopes;
                setScopes(arrRequestedScopes);
            }
        }
        if (jsonObjectRequestedClaims.get(STATE) != null) {
            setState(jsonObjectRequestedClaims.get(STATE).toString());
        }
        if (jsonObjectRequestedClaims.get(NONCE) != null) {
            setNonce(jsonObjectRequestedClaims.get(NONCE).toString());
        }
        if (jsonObjectRequestedClaims.get(ISS) != null) {
            setIss(jsonObjectRequestedClaims.get(ISS).toString());
        }
        if (jsonObjectRequestedClaims.get(AUD) != null) {
            setAud(jsonObjectRequestedClaims.get(AUD).toString());
        }
        if (jsonObjectRequestedClaims.get(RESPONSE_TYPE) != null) {
            setResponseType(jsonObjectRequestedClaims.get(RESPONSE_TYPE).toString());
        }
        if (jsonObjectRequestedClaims.get(MAX_AGE) != null) {
            setMaxAge(jsonObjectRequestedClaims.get(MAX_AGE).toString());
        }
    }

    public boolean isValidJson() {
        return isValidJson;
    }

    public void setIsJson(boolean isJson) {
        this.isValidJson = isJson;
    }

    public Map<String, List<Claim>> getClaimsforRequestParameter() {
        return claimsforRequestParameter;
    }

    public void setClaimsforRequestParameter(Map<String, List<Claim>> claimsforRequestParameter) {
        this.claimsforRequestParameter = claimsforRequestParameter;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(String maxAge) {
        this.maxAge = maxAge;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public boolean isSignatureValid() {
        return isSignatureValid;
    }

    public void setIsSignatureValid(boolean isSignatureValid) {
        this.isSignatureValid = isSignatureValid;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
    }

    public String[] getScopes() {
        return scopes;
    }

    public void setScopes(String[] scopes) {
        DefaultRequestObject.scopes = scopes;
    }

    private SignedJWT getSignedJWT(String requestObject) {

        SignedJWT signedJWT = null;
        try {
            signedJWT = SignedJWT.parse(requestObject);
        } catch (java.text.ParseException e) {
            log.error("Error occured while passing the jwt");
        }
        return signedJWT;
    }

    public boolean isValidRequestURI() {
        return isValidRequestURI;
    }

    public void setIsValidRequestURI(boolean isValidRequestURI) {
        this.isValidRequestURI = isValidRequestURI;
    }
}
