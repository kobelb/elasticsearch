/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */
package org.elasticsearch.cluster.metadata;

import org.elasticsearch.TransportVersion;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.index.Index;
import org.elasticsearch.xcontent.ConstructingObjectParser;
import org.elasticsearch.xcontent.ParseField;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * Represents a single view definition, which is a name, a query string, and optional metadata.
 */
public final class View implements Writeable, ToXContentObject, IndexAbstraction {
    private static final ParseField NAME = new ParseField("name");
    private static final ParseField QUERY = new ParseField("query");
    private static final ParseField ALLOW_RESTRICTED_INDICES = new ParseField("allow_restricted_indices");

    /**
     * Transport version that introduced the {@code allow_restricted_indices} field on views.
     * Views with this flag bypass the system-index access gate when resolved via ES|QL,
     * allowing privileged callers (e.g. Kibana running as operator) to back a view with a
     * system index. Setting the flag requires operator privileges on the PUT view API.
     */
    public static final TransportVersion VIEW_ALLOW_RESTRICTED_INDICES = TransportVersion.fromName("view_allow_restricted_indices");

    // Parser that includes the name field (eg. serializing/deserializing the full object)
    static final ConstructingObjectParser<View, Void> PARSER = new ConstructingObjectParser<>(
        "view",
        false,
        (args, ctx) -> new View((String) args[0], (String) args[1], args[2] != null && (boolean) args[2])
    );

    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), NAME);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), QUERY);
        PARSER.declareBoolean(ConstructingObjectParser.optionalConstructorArg(), ALLOW_RESTRICTED_INDICES);
    }

    // Parser that excludes the name field (eg. when the name is provided externally, in the URL path)
    public static ConstructingObjectParser<View, Void> parser(String name) {
        ConstructingObjectParser<View, Void> parser = new ConstructingObjectParser<>(
            "view",
            false,
            (args, ctx) -> new View(name, (String) args[0], args[1] != null && (boolean) args[1])
        );
        parser.declareString(ConstructingObjectParser.constructorArg(), QUERY);
        parser.declareBoolean(ConstructingObjectParser.optionalConstructorArg(), ALLOW_RESTRICTED_INDICES);
        return parser;
    }

    private final String name;
    private final String query;
    private final boolean allowRestrictedIndices;

    public View(String name, String query) {
        this(name, query, false);
    }

    public View(String name, String query, boolean allowRestrictedIndices) {
        this.name = Objects.requireNonNull(name, "view name must not be null");
        this.query = Objects.requireNonNull(query, "view query must not be null");
        this.allowRestrictedIndices = allowRestrictedIndices;
    }

    public View(StreamInput in) throws IOException {
        this.name = in.readString();
        this.query = in.readString();
        this.allowRestrictedIndices = in.getTransportVersion().supports(VIEW_ALLOW_RESTRICTED_INDICES) && in.readBoolean();
    }

    public static View fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(query);
        if (out.getTransportVersion().supports(VIEW_ALLOW_RESTRICTED_INDICES)) {
            out.writeBoolean(allowRestrictedIndices);
        }
    }

    public String name() {
        return name;
    }

    public String query() {
        return query;
    }

    /**
     * When {@code true}, ES|QL view resolution will bypass the system-index access gate for
     * indices referenced in this view's query body. This allows a view backed by a system index
     * to be queried by users whose only relevant grant comes from an implicit privilege with
     * {@code allow_restricted_indices: true}. Setting this flag requires operator privileges.
     */
    public boolean allowRestrictedIndices() {
        return allowRestrictedIndices;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME.getPreferredName(), name);
        builder.field(QUERY.getPreferredName(), query);
        if (allowRestrictedIndices) {
            builder.field(ALLOW_RESTRICTED_INDICES.getPreferredName(), allowRestrictedIndices);
        }
        builder.endObject();
        return builder;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        View other = (View) o;
        return Objects.equals(name, other.name)
            && Objects.equals(query, other.query)
            && allowRestrictedIndices == other.allowRestrictedIndices;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, query, allowRestrictedIndices);
    }

    public String toString() {
        return Strings.toString(this);
    }

    @Override
    public Type getType() {
        return Type.VIEW;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public List<Index> getIndices() {
        return List.of();
    }

    @Override
    public Index getWriteIndex() {
        return null;
    }

    @Override
    public DataStream getParentDataStream() {
        return null;
    }

    @Override
    public boolean isHidden() {
        return false;
    }

    @Override
    public boolean isSystem() {
        return false;
    }
}
