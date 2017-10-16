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

/**
 * Validates Request Object
 */
public interface RequestObjectValidator {

    /**
     * Validates Signature of the requestObject jwt
     *
     * @param requestObject
     * @return true if signature is valid
     */
    public boolean isSignatureValid(String requestObject);

    /**
     * For customized validations
     *
     * @param Object
     * @return true if customize validations are valid
     */
    public boolean isObjectValid(String Object);

    /** For requestURI validations
     *
     * @param url
     * @return true if requestUri is valid
     */
    public boolean isRequestUriValid(String url);

}
