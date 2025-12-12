/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.kibana;

import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;

import java.util.List;

public class AlertsDlsSecurityExtension implements SecurityExtension
{
    @Override
    public List<DlsQueryExtension> getDocumentLevelSecurityExtensions(SecurityComponents components) {
        return List.of(new AlertsDlsQueryExtension(components.client()));
    }
}
