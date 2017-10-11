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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.LocalRole;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.when;

public class ClaimUtilTest {

    @Mock
    ServiceProvider mockedServiceProvider;

    @Mock
    PermissionsAndRoleConfig mockedPermissionAndRoleConfig;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @DataProvider(name = "provideRoleMappingData")
    public Object[][] provideRoleMappingData() {

        //Setting SP role mappings
        RoleMapping[] roleMappings = new RoleMapping[2];
        LocalRole role1 = new LocalRole("PRIMARY", "role1");
        LocalRole role2 = new LocalRole("PRIMARY", "role2");

        RoleMapping mapping1 = new RoleMapping(role1, "remoteRole1");
        RoleMapping mapping2 = new RoleMapping(role2, "remoteRole2");

        roleMappings[0] = mapping1;
        roleMappings[1] = mapping2;

        // locallyMappedUserRoles, roleMappingObject, claimSeparator, expectedRoles
        return new Object[][]{
                {
                        // No Local Roles to Map to SP Roles.
                        new ArrayList<String>(),
                        roleMappings,
                        ",",
                        null
                },
                {
                        null,
                        null,
                        ",",
                        null
                },
                {
                        // No SP to Local Role mappings.
                        new ArrayList<String>() {{
                            add("role1");
                            add("role2");
                        }},
                        null,
                        ",,,",
                        "role1,,,role2"
                },
                {
                        // Complete SP to Local Role mappings.
                        new ArrayList<String>() {{
                            add("role1");
                            add("role2");
                        }},
                        roleMappings,
                        "#",
                        "remoteRole1#remoteRole2"
                },
                {
                        // Partial SP to Local Role mappings.
                        new ArrayList<String>() {{
                            add("role1");
                            add("role3");
                        }},
                        roleMappings,
                        "#",
                        "remoteRole1#role3"
                },
                {
                        // No SP to Local Role mappings.
                        new ArrayList<String>() {{
                            add("role1");
                        }},
                        new RoleMapping[0],
                        ",",
                        "role1"
                }
        };
    }

    @Test(dataProvider = "provideRoleMappingData")
    public void testGetServiceProviderMappedUserRoles(List<String> locallyMappedUserRoles,
                                                      Object roleMappingObject,
                                                      String claimSeparator,
                                                      String expected) throws Exception {

        RoleMapping[] roleMappings = (RoleMapping[]) roleMappingObject;
        when(mockedPermissionAndRoleConfig.getRoleMappings()).thenReturn(roleMappings);
        when(mockedServiceProvider.getPermissionAndRoleConfig()).thenReturn(mockedPermissionAndRoleConfig);
        String returned = ClaimUtil.getServiceProviderMappedUserRoles(mockedServiceProvider,
                locallyMappedUserRoles, claimSeparator);
        Assert.assertEquals(returned, expected, "Invalid returned value");
    }

}
