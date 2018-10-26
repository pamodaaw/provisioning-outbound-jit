/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.post.authentication.provisioning;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.post.authentication.provisioning.internal.DataHolder;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.OutboundProvisioningManager;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JitOutboundProvisioningPostAuthHandler extends AbstractPostAuthnHandler {

    private static volatile JitOutboundProvisioningPostAuthHandler instance = new
            JitOutboundProvisioningPostAuthHandler();
    private static Log log = LogFactory.getLog(JitOutboundProvisioningPostAuthHandler.class);

    private String CONSENT_POPPED_UP = "consentPoppedUp";

    public static JitOutboundProvisioningPostAuthHandler getInstance() {
        return instance;
    }

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest httpServletRequest,
                                             HttpServletResponse httpServletResponse,
                                             AuthenticationContext authenticationContext)
            throws PostAuthenticationFailedException {

        try {
            callProvisioningConnector(authenticationContext);
        } catch (UserStoreException | CarbonException e) {
            e.printStackTrace();
        }

        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;

    }

    @Override
    public String getName() {

        return "JitOutboundProvisioningPostAuthHandler";
    }

    private boolean callProvisioningConnector(AuthenticationContext authenticationContext) throws
            UserStoreException, CarbonException {

        String userName = authenticationContext.getLastAuthenticatedUser().getUserName();
        String tenantDomain = authenticationContext.getTenantDomain();
        String serviceProviderName = authenticationContext.getServiceProviderName();

        RegistryService registryService = DataHolder.getInstance().getRegistryService();
        RealmService realmService = DataHolder.getInstance().getRealmService();
        UserRealm realm = AnonymousSessionUtil.getRealmByTenantDomain(registryService, realmService, tenantDomain);
        UserStoreManager userStoreManager = realm.getUserStoreManager();

        Map<String, String> inboundAttributes = new HashMap<>();
        Map<ClaimMapping, List<String>> outboundAttributes = new HashMap<>();

        if (userName != null) {
            outboundAttributes.put(ClaimMapping.build(
                    IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, null, false),
                    Arrays.asList(new String[]{userName}));
        }

        String domainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        if (log.isDebugEnabled()) {
            log.debug("Adding domain name : " + domainName + " to user : " + userName);
        }
        String domainAwareName = UserCoreUtil.addDomainToName(userName, domainName);

        ProvisioningEntity provisioningEntity = new ProvisioningEntity(
                ProvisioningEntityType.USER, domainAwareName, ProvisioningOperation.POST,
                outboundAttributes);

        Claim[] claimArray = null;
        try {
            claimArray = userStoreManager.getUserClaimValues(userName, null);
        } catch (UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + userName + " not found in user store");
                }
            } else {
                throw e;
            }
        }
        if (claimArray != null) {
            for (Claim claim : claimArray) {
                inboundAttributes.put(claim.getClaimUri(), claim.getValue());
            }
        }

        provisioningEntity.setInboundAttributes(inboundAttributes);

        // call framework method to provision the user.
        OutboundProvisioningManager.getInstance().provision(provisioningEntity,
                serviceProviderName, IdentityProvisioningConstants.WSO2_CARBON_DIALECT,
                tenantDomain, false);

        return true;
    }

}
//
//    private void setConsentPoppedUpState(AuthenticationContext authenticationContext) {
//
//        authenticationContext.addParameter(CONSENT_POPPED_UP, true);
//    }
//
//    private boolean isConsentPoppedUp(AuthenticationContext authenticationContext) {
//
//        return authenticationContext.getParameter(CONSENT_POPPED_UP) != null;
//    }
