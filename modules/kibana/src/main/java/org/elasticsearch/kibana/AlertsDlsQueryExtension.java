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
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.Strings;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.xpack.core.security.action.user.GetUserPrivilegesRequestBuilder;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.ResolvedIndices;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.ResourcePrivileges;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.permission.StaticSecurityQuery;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class AlertsDlsQueryExtension implements DlsQueryExtension {

    private static final Pattern spaceResourcePattern = Pattern.compile("^space:(.*)");
    private static final String SPACES = "spaces";
    private static final String INDEX_PREFIX = ".alerts-";
    private static final String APP_NAME = "kibana-.kibana";
    private static final String READ_PRIVILEGE = "saved_object:alert/find"; //TODO: Replace this with the actual action we want to use
    private final Logger logger = LogManager.getLogger(AlertsDlsQueryExtension.class);
    private final Client client;

    public AlertsDlsQueryExtension(Client client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "kibana_alerts";
    }

    @Override
    public DocumentSecurityQuery build(User user, Map<String, Object> config, RequestData data) {
        this.logger.debug("AlertsDlsQueryExtension::build");
        if (data == null) {
            throw new IllegalStateException("no request data provided");
        }
        final Collection<String> spaces = data.get(SPACES);
        if (spaces == null) {
            throw new IllegalStateException("request data does not contain [" + SPACES + "]");
        }
        if (spaces.isEmpty()) {
            return StaticSecurityQuery.MATCH_NONE;
        }

        final String query = Strings.format("""
            { "terms": { "kibana.space_ids": [  %s ] } }
            """, spaces.stream().map(s -> '"' + s + '"').collect(Collectors.joining(", ")));
        logger.info("using DLS query [{}]", query);
        return new StaticSecurityQuery(query);
    }

    // The goal is to determine all spaces where the user is authorized to search alerts.
    // This can't be done in a single operation because the role definitions tell us the spaces
    // and then the application privilege definition tell us which privileges are for the alerts.
    // Therefore, first we will call GET _security/user/_privileges to get all resources,
    // which happen to be the space, and then we call GET _security/_has_privileges
    // to determine the actual spaces that the user is authorized to see the alerts from.
    @Override
    public void precache(Authentication authentication, Role role, ResolvedIndices requestedIndices, ActionListener<RequestData> listener) {
        this.logger.debug("AlertsDlsQueryExtension::precache");
        if (requestedIndices.getLocal().stream().anyMatch(index -> index.startsWith(INDEX_PREFIX))) {
            var user = authentication.getEffectiveSubject().getUser();
            final GetUserPrivilegesRequestBuilder getUserPrivilegesRequest = new GetUserPrivilegesRequestBuilder(this.client).username(user.principal());
            getUserPrivilegesRequest.execute(listener.delegateFailureAndWrap((l, getUserPrivilegesResponse) -> {
                final Set<String> resources = getUserPrivilegesResponse.getApplicationPrivileges()
                    .stream()
                    .map(RoleDescriptor.ApplicationResourcePrivileges::getResources)
                    .flatMap(Arrays::stream)
                    .collect(Collectors.toSet());

                final RoleDescriptor.ApplicationResourcePrivileges applicationPrivileges = RoleDescriptor.ApplicationResourcePrivileges.builder()
                    .application(APP_NAME)
                    .privileges(READ_PRIVILEGE)
                    .resources(resources)
                    .build();

                final HasPrivilegesRequest req = new HasPrivilegesRequest();
                req.username(user.principal());
                req.clusterPrivileges(Strings.EMPTY_ARRAY);
                req.indexPrivileges(new RoleDescriptor.IndicesPrivileges[0]);
                req.applicationPrivileges(applicationPrivileges);
                client.execute(HasPrivilegesAction.INSTANCE, req, l.map(response -> {
                    final List<String> spaces = response.getApplicationPrivileges()
                        .get(APP_NAME)
                        .stream()
                        .filter(priv -> priv.getPrivileges().get(READ_PRIVILEGE))
                        .map(ResourcePrivileges::getResource)
                        .map(resource -> {
                            Matcher matcher = spaceResourcePattern.matcher(resource);
                            if (matcher.find()) {
                                return matcher.group(1);
                            }
                            throw new IllegalStateException("Space resource [" + resource + "] did not match [" + spaceResourcePattern.pattern() + "]");
                        })
                        .toList();
                    return new RequestData(Map.of(SPACES, spaces));
                }));
            }));
        } else {
            listener.onResponse(RequestData.EMPTY);
        }
    }
}
