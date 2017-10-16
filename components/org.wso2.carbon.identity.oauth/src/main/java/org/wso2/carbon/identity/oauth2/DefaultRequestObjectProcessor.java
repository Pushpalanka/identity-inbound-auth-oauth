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

import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.RequestObjectProcessor;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * This class processes the request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class DefaultRequestObjectProcessor implements RequestObjectProcessor {

    private static Log log = LogFactory.getLog(DefaultRequestObjectValidator.class);
    private static String CLAIMS = "claims";
    private static String ESSENTIAL = "essential";

    /**
     * This method returns list of essential claims according to the request object content.
     *
     * @param requestObject requested claims
     * @param member          member can be userinfo endpoint or the id token
     * @return requested claims
     */
    @Override
    public ArrayList<String> getEssentialClaimsofRequestParam(String requestObject, String member) {
        JSONParser parser = new JSONParser();
        ArrayList essentialClaimsRequestParam = new ArrayList();
        JSONObject jsonObjectEssentialClaims = null;
        try {
            if (!OAuth2Util.isJSON(requestObject)) {
                SignedJWT signedJWT = getSignedJWT(requestObject);
                if (signedJWT != null && signedJWT.getPayload() != null) {
                    requestObject = new String(Base64.decodeBase64(getSignedJWT(requestObject).getPayload().toString().
                            getBytes(Charsets.UTF_8)), Charsets.UTF_8);
                }
            }
            JSONObject jsonObjectRequestedClaims = (JSONObject) parser.parse(requestObject);
            JSONObject jsonObjectMember = null;
            if (jsonObjectRequestedClaims.get(CLAIMS) != null) {
                jsonObjectMember = (JSONObject) parser.parse(jsonObjectRequestedClaims.get(CLAIMS).toString());
            }
            if (jsonObjectMember.get(member) != null) {
                JSONObject jsonObjectClaims = (JSONObject) parser.parse(jsonObjectMember.get(member).toString());
                for (Iterator iterator = jsonObjectClaims.keySet().iterator(); iterator.hasNext(); ) {
                    String essentialKey = (String) iterator.next();
                    if (jsonObjectClaims.get(essentialKey) != null) {
                        jsonObjectEssentialClaims = (JSONObject) parser.parse(jsonObjectClaims.get(essentialKey).toString());
                        if ((jsonObjectEssentialClaims.get(ESSENTIAL) != null)) {
                            String essentialValue = jsonObjectEssentialClaims.get(ESSENTIAL).toString();
                            if (Boolean.parseBoolean(essentialValue)) {
                                essentialClaimsRequestParam.add(essentialKey);
                            }
                        }
                    }

                }
            }
        } catch (ParseException e) {
            log.error("Failed to process the request Object.");
        }
        return essentialClaimsRequestParam;
    }

    @Override
    public String getRequestUriParam() {
        return null;
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

}
