/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */
package org.elasticsearch.cluster.metadata;

import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.test.AbstractXContentSerializingTestCase;
import org.elasticsearch.test.TransportVersionUtils;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;

import static org.elasticsearch.cluster.metadata.View.VIEW_ALLOW_RESTRICTED_INDICES;
import static org.elasticsearch.cluster.metadata.ViewTestsUtils.randomName;
import static org.elasticsearch.cluster.metadata.ViewTestsUtils.randomView;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class ViewTests extends AbstractXContentSerializingTestCase<View> {

    @Override
    protected View doParseInstance(XContentParser parser) throws IOException {
        return View.fromXContent(parser);
    }

    @Override
    protected View createTestInstance() {
        return randomView(randomName());
    }

    @Override
    protected View mutateInstance(View instance) {
        return randomValueOtherThan(instance, () -> randomView(instance.name()));
    }

    @Override
    protected Writeable.Reader<View> instanceReader() {
        return View::new;
    }

    @Override
    protected void assertEqualInstances(View expectedInstance, View newInstance) {
        assertNotSame(expectedInstance, newInstance);
        assertEqualViews(expectedInstance, newInstance);
    }

    public static void assertEqualViews(View expectedInstance, View newInstance) {
        assertThat(newInstance.query(), equalTo(expectedInstance.query()));
        assertThat(newInstance.allowRestrictedIndices(), equalTo(expectedInstance.allowRestrictedIndices()));
    }

    public void testSerializationRoundTripAllowRestrictedIndices() throws IOException {
        View view = new View(randomName(), "FROM test", true);
        BytesStreamOutput out = new BytesStreamOutput();
        view.writeTo(out);
        View read = new View(out.bytes().streamInput());
        assertThat(read.allowRestrictedIndices(), is(true));
    }

    public void testSerializationBwcAllowRestrictedIndicesDefaultsFalse() throws IOException {
        View view = new View(randomName(), "FROM test", true);
        BytesStreamOutput out = new BytesStreamOutput();
        var oldVersion = TransportVersionUtils.randomVersionNotSupporting(VIEW_ALLOW_RESTRICTED_INDICES);
        out.setTransportVersion(oldVersion);
        view.writeTo(out);

        var in = out.bytes().streamInput();
        in.setTransportVersion(oldVersion);
        View read = new View(in);
        assertThat(read.allowRestrictedIndices(), is(false));
    }
}
