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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.post.authentication.provisioning.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.identity.post.authentication.provisioning.JitOutboundProvisioningPostAuthHandler;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Registers the connector as an osgi component.
 */
@Component(
        name = "identity.outbound.provisioning.jit.component",
        immediate = true
)
public class JitOutboundProvisioningServiceComponent {

    private static Log log = LogFactory.getLog(JitOutboundProvisioningServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Activating JIT outbound provisioning component");
        }
        JitOutboundProvisioningPostAuthHandler postAuthenticationHandler = new
                JitOutboundProvisioningPostAuthHandler();
        try {
            context.getBundleContext().registerService(PostAuthenticationHandler.class.getName(),
                    postAuthenticationHandler, null);
            if (log.isDebugEnabled()) {
                log.debug("JIT outbound provisioning component is activated.");
            }
        } catch (Throwable e) {
            log.error("Error while activating JIT outbound provisioning component.", e);
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Application Authentication Framework bundle");
        }
        DataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Application Authentication Framework bundle");
        }
        DataHolder.getInstance().setRealmService(null);
    }
    @Reference(
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is set in the Application Authentication Framework bundle");
        }

        DataHolder.getInstance().setRegistryService(registryService);
    }
    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Application Authentication Framework bundle");
        }
        DataHolder.getInstance().setRealmService(null);
    }
}
