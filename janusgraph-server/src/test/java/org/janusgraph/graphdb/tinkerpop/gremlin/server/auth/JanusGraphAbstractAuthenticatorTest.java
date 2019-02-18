// Copyright 2019 JanusGraph Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.janusgraph.graphdb.tinkerpop.gremlin.server.auth;

import org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens;
import org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialTraversalSource;
import org.apache.tinkerpop.gremlin.server.auth.SimpleAuthenticator;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.easymock.EasyMockSupport;
import org.janusgraph.StorageSetup;
import org.janusgraph.core.Cardinality;
import org.janusgraph.core.JanusGraph;
import org.janusgraph.core.PropertyKey;
import org.janusgraph.core.schema.JanusGraphIndex;
import org.janusgraph.core.schema.SchemaStatus;
import org.janusgraph.graphdb.database.management.ManagementSystem;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.tinkerpop.gremlin.server.auth.SimpleAuthenticator.CONFIG_CREDENTIALS_DB;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.isA;
import static org.junit.jupiter.api.Assertions.*;

public abstract class JanusGraphAbstractAuthenticatorTest extends EasyMockSupport {

    public abstract JanusGraphAbstractAuthenticator createAuthenticator();

    public abstract ConfigBuilder configBuilder();

    @Test
    public void testSetupNullConfig() {
        final JanusGraphAbstractAuthenticator authenticator = createAuthenticator();

        assertThrows(IllegalArgumentException.class, () -> authenticator.setup(null));
    }

    @Test
    public void testSetupNoCredDb() {
        final JanusGraphAbstractAuthenticator authenticator = createAuthenticator();

        assertThrows(IllegalStateException.class, () -> authenticator.setup(new HashMap<>()));
    }

    @Test
    public void testSetupNoUserDefault() {
        final JanusGraphAbstractAuthenticator authenticator = createAuthenticator();
        final Map<String, Object> configMap = configBuilder().defaultPassword("pass").create();

        assertThrows(IllegalStateException.class, () -> authenticator.setup(configMap));
    }

    @Test
    public void testSetupNoPassDefault() {
        final JanusGraphAbstractAuthenticator authenticator = createAuthenticator();
        final Map<String, Object> configMap = configBuilder().defaultUser("user").create();

        assertThrows(IllegalStateException.class, () -> authenticator.setup(configMap));
    }

    @Test
    public void testSetupEmptyCredentialsGraphCreateDefaultUser() {
        final JanusGraphSimpleAuthenticator authenticator = createMockBuilder(JanusGraphSimpleAuthenticator.class)
            .addMockedMethod("openGraph")
            .addMockedMethod("createSimpleAuthenticator")
            .createMock();
        final JanusGraph graph = StorageSetup.getInMemoryGraph();
        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        final SimpleAuthenticator sa = createMock(SimpleAuthenticator.class);
        expect(authenticator.createSimpleAuthenticator()).andReturn(sa);
        final String defaultUser = "user";
        final String defaultPassword = "pass";
        final Map<String, Object> configMap =
            configBuilder().defaultUser(defaultUser).defaultPassword(defaultPassword).create();
        sa.setup(configMap);
        replayAll();

        authenticator.setup(configBuilder().defaultUser(defaultUser).defaultPassword(defaultPassword).create());

        CredentialTraversalSource credentialSource = graph.traversal(CredentialTraversalSource.class);
        List<Vertex> users = credentialSource.users(defaultUser).toList();
        assertEquals(1, users.size());
    }

    @Test
    public void testSetupEmptyCredentialsGraphCreateUsernamePropertyKey() {
        final JanusGraphSimpleAuthenticator authenticator = createMockBuilder(JanusGraphSimpleAuthenticator.class)
            .addMockedMethod("openGraph")
            .addMockedMethod("createSimpleAuthenticator")
            .createMock();
        final JanusGraph graph = StorageSetup.getInMemoryGraph();
        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        final SimpleAuthenticator sa = createMock(SimpleAuthenticator.class);
        expect(authenticator.createSimpleAuthenticator()).andReturn(sa);
        final Map<String, Object> configMap = createConfig();
        sa.setup(configMap);
        replayAll();

        authenticator.setup(configMap);

        final ManagementSystem mgmt = (ManagementSystem) graph.openManagement();
        final PropertyKey username = mgmt.getPropertyKey(CredentialGraphTokens.PROPERTY_USERNAME);
        assertEquals(String.class, username.dataType());
        assertEquals(Cardinality.SINGLE, username.cardinality());
    }

    @Test
    public void testSetupEmptyCredentialsGraphCreateUsernameIndex() {
        final JanusGraphSimpleAuthenticator authenticator = createMockBuilder(JanusGraphSimpleAuthenticator.class)
            .addMockedMethod("openGraph")
            .addMockedMethod("createSimpleAuthenticator")
            .createMock();
        final JanusGraph graph = StorageSetup.getInMemoryGraph();
        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        final SimpleAuthenticator sa = createMock(SimpleAuthenticator.class);
        expect(authenticator.createSimpleAuthenticator()).andReturn(sa);
        final Map<String, Object> configMap = createConfig();
        sa.setup(configMap);
        replayAll();

        authenticator.setup(configMap);

        final ManagementSystem mgmt = (ManagementSystem) graph.openManagement();
        assertTrue(mgmt.containsGraphIndex(JanusGraphSimpleAuthenticator.USERNAME_INDEX_NAME));
        final JanusGraphIndex index = mgmt.getGraphIndex(JanusGraphSimpleAuthenticator.USERNAME_INDEX_NAME);
        final PropertyKey username = mgmt.getPropertyKey(CredentialGraphTokens.PROPERTY_USERNAME);
        assertTrue(index.getIndexStatus(username).equals(SchemaStatus.ENABLED));
    }

    private Map<String, Object> createConfig() {
        return configBuilder().defaultUser("testUser").defaultPassword("testPassword").create();
    }

    private Map<String, Object> createConfig(final String defaultUser, final String defaultPassword) {
        final Map<String, Object> config = new HashMap<>();
        config.put(CONFIG_CREDENTIALS_DB, "configCredDb");
        config.put(JanusGraphSimpleAuthenticator.CONFIG_DEFAULT_PASSWORD, defaultPassword);
        config.put(JanusGraphSimpleAuthenticator.CONFIG_DEFAULT_USER, defaultUser);
        return config;
    }
}
