/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.kibana;

import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.ext.DynamicRoleAssigner;
import org.elasticsearch.xpack.core.security.support.StringMatcher;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Stream;

import static org.elasticsearch.kibana.KibanaPlugin.KIBANA_APPLICATION_PRIVILEGE;

public class AlertsDynamicRoleAssigner implements DynamicRoleAssigner {
    @Override
    public Set<String> additionalRoles(Collection<RoleDescriptor> primaryRoles) {
        if (primaryRoles.stream().anyMatch(AlertsDynamicRoleAssigner::hasTestApplicationPrivilege)) {
            return Set.of(AlertsDynamicRoleProvider.ROLE_NAME);
        } else {
            return Set.of();
        }

    }

    private static boolean hasTestApplicationPrivilege(RoleDescriptor rd) {
        return Stream.of(rd.getApplicationPrivileges()).anyMatch(ap -> StringMatcher.of(ap.getApplication()).test(KIBANA_APPLICATION_PRIVILEGE));
    }
}
