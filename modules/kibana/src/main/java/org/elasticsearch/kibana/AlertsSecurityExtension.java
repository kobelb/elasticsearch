/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.kibana;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;
import org.elasticsearch.xpack.core.security.ext.DynamicRoleAssigner;

import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

public class AlertsSecurityExtension implements SecurityExtension
{
    @Override
    public List<DlsQueryExtension> getDocumentLevelSecurityExtensions(SecurityComponents components) {
        return List.of(new AlertsDlsQueryExtension(components.client()));
    }

    @Override
    public List<DynamicRoleAssigner> getDynamicRoleAssigners(SecurityComponents components) {
        return List.of(new AlertsDynamicRoleAssigner());
    }

    @Override
    public List<BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>>> getRolesProviders(SecurityComponents components) {
        return List.of(new AlertsDynamicRoleProvider());
    }
}
