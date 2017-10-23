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


import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * This interface is used to model the request object which comes as a parameter of the OIDC authorization request
 */
public interface RequestObject extends Serializable {
    static final long serialVersionUID = -4449780649560053452L;

    public void processRequestObject(String requestObject);

    public Map<String, List<Claim>> getClaimsforRequestParameter();

    public String getRedirectUri();

    public String getState();

    public String getNonce();

    public String getIss();

    public String getAud();

    public String getResponseType();

    public String getMaxAge();

    public String getClientId();

    public boolean isSignatureValid();

    public Map<String, Object> getProperties();

    public boolean isValidJson();

    public String[] getScopes();

    public boolean isValidRequestURI();

}
