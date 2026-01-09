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
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;

import java.util.Set;
import java.util.function.BiConsumer;

public class AlertsDynamicRoleProvider implements BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>> {
    public static final String ROLE_NAME = "@kibana_alerts";
    private final RoleDescriptor descriptor;

    public AlertsDynamicRoleProvider() {
        this.descriptor = new RoleDescriptor(
            ROLE_NAME,
            null,
            new RoleDescriptor.IndicesPrivileges[] {
                RoleDescriptor.IndicesPrivileges.builder().indices(".alerts-*").privileges("read").query("{ \"extension\": { \"name\": \"kibana_alerts\" } }").build() },
            null
        );
    }

    @Override
    public void accept(Set<String> roleNames, ActionListener<RoleRetrievalResult> listener) {

        if (roleNames.contains(ROLE_NAME)) {
            listener.onResponse(RoleRetrievalResult.success(Set.of(descriptor)));
        } else {
            listener.onResponse(RoleRetrievalResult.success(Set.of()));
        }
    }
}
