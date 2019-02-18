// Copyright 2017 JanusGraph Authors
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

import static org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens.PROPERTY_USERNAME;
import static org.apache.tinkerpop.gremlin.server.auth.SimpleAuthenticator.CONFIG_CREDENTIALS_DB;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.isA;
import static org.janusgraph.graphdb.tinkerpop.gremlin.server.handler.HttpHMACAuthenticationHandler.PROPERTY_TOKEN;
import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

import org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialTraversalSource;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticationException;
import org.apache.tinkerpop.gremlin.structure.Transaction;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.janusgraph.StorageSetup;
import org.janusgraph.core.Cardinality;
import org.janusgraph.core.JanusGraph;
import org.janusgraph.core.PropertyKey;
import org.janusgraph.core.schema.JanusGraphIndex;
import org.janusgraph.core.schema.JanusGraphManagement;
import org.janusgraph.core.schema.PropertyKeyMaker;
import org.janusgraph.core.schema.SchemaStatus;
import org.janusgraph.graphdb.database.management.ManagementSystem;
import org.junit.jupiter.api.Test;

public class HMACAuthenticatorTest extends JanusGraphAbstractAuthenticatorTest {

    @Override
    public JanusGraphAbstractAuthenticator createAuthenticator() {
        return new HMACAuthenticator();
    }

    @Override
    public ConfigBuilder configBuilder() {
        return HmacConfigBuilder.build();
    }

    @Test
    public void testSetupNoHmacSecret() {
        final HMACAuthenticator authenticator = new HMACAuthenticator();
        final Map<String, Object> configMap = new HashMap<>();
        configMap.put(CONFIG_CREDENTIALS_DB, "configCredDb");

        assertThrows(IllegalStateException.class, () -> authenticator.setup(configMap));
    }

    @Test
    public void testSetupEmptyCredGraphNoUserIndex() {
        final HMACAuthenticator authenticator = createMockBuilder(HMACAuthenticator.class)
            .addMockedMethod("openGraph")
            .addMockedMethod("createCredentialGraph")
            .createMock();

        final Map<String, Object> configMap = new HashMap<String, Object>();
        configMap.put(CONFIG_CREDENTIALS_DB, "configCredDb");
        configMap.put(HMACAuthenticator.CONFIG_HMAC_SECRET, "secret");
        configMap.put(HMACAuthenticator.CONFIG_DEFAULT_PASSWORD, "pass");
        configMap.put(HMACAuthenticator.CONFIG_DEFAULT_USER, "user");

        final JanusGraph graph = createMock(JanusGraph.class);
        final CredentialTraversalSource credentialTraversalSource = createMock(CredentialTraversalSource.class);
        final ManagementSystem mgmt = createMock(ManagementSystem.class);
        final Transaction tx = createMock(Transaction.class);
        final PropertyKey pk = createMock(PropertyKey.class);
        final PropertyKeyMaker pkm = createMock(PropertyKeyMaker.class);
        final JanusGraphManagement.IndexBuilder indexBuilder = createMock(JanusGraphManagement.IndexBuilder.class);
        final JanusGraphIndex index = createMock(JanusGraphIndex.class);
        final PropertyKey[] pks = {pk};

        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        expect(authenticator.createCredentials(isA(JanusGraph.class))).andReturn(credentialTraversalSource);
        expect(credentialTraversalSource.users("user")).andReturn(null);
        expect(credentialTraversalSource.user(eq("user"), eq("pass"))).andReturn(null);
        expect(graph.openManagement()).andReturn(mgmt).times(2);
        expect(graph.tx()).andReturn(tx);
        expect(index.getFieldKeys()).andReturn(pks);
        expect(index.getIndexStatus(eq(pk))).andReturn(SchemaStatus.ENABLED);

        tx.rollback();
        expectLastCall();

        expect(mgmt.containsGraphIndex(eq("byUsername"))).andReturn(false);
        expect(mgmt.makePropertyKey(PROPERTY_USERNAME)).andReturn(pkm);
        expect(pkm.dataType(eq(String.class))).andReturn(pkm);
        expect(pkm.cardinality(Cardinality.SINGLE)).andReturn(pkm);
        expect(pkm.make()).andReturn(pk);
        expect(mgmt.buildIndex(eq("byUsername"), eq(Vertex.class))).andReturn(indexBuilder);
        expect(mgmt.getGraphIndex(eq("byUsername"))).andReturn(index);
        expect(indexBuilder.addKey(eq(pk))).andReturn(indexBuilder);
        expect(indexBuilder.unique()).andReturn(indexBuilder);
        expect(indexBuilder.buildCompositeIndex()).andReturn(index);

        mgmt.commit();
        expectLastCall();

        mgmt.rollback();
        expectLastCall();

        replayAll();

        authenticator.setup(configMap);
    }

    @Test
    public void testPassEmptyCredGraphUserIndex() {
        final HMACAuthenticator authenticator = createMockBuilder(HMACAuthenticator.class)
            .addMockedMethod("openGraph")
            .addMockedMethod("createCredentialGraph")
            .createMock();

        final Map<String, Object> configMap = new HashMap<>();
        configMap.put(CONFIG_CREDENTIALS_DB, "configCredDb");
        configMap.put(HMACAuthenticator.CONFIG_HMAC_SECRET, "secret");
        configMap.put(HMACAuthenticator.CONFIG_DEFAULT_PASSWORD, "pass");
        configMap.put(HMACAuthenticator.CONFIG_DEFAULT_USER, "user");

        final JanusGraph graph = createMock(JanusGraph.class);
        final CredentialTraversalSource credentialTraversalSource = createMock(CredentialTraversalSource.class);
        final ManagementSystem mgmt = createMock(ManagementSystem.class);
        final Transaction tx = createMock(Transaction.class);

        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        expect(authenticator.createCredentials(isA(JanusGraph.class))).andReturn(credentialTraversalSource);
        expect(mgmt.containsGraphIndex(eq("byUsername"))).andReturn(true);
        expect(credentialTraversalSource.users("user")).andReturn(null);
        expect(credentialTraversalSource.user(eq("user"), eq("pass"))).andReturn(null);
        expect(graph.openManagement()).andReturn(mgmt);
        expect(graph.tx()).andReturn(tx);
        tx.rollback();
        expectLastCall();
        replayAll();

        authenticator.setup(configMap);
    }

    @Test
    public void testSetupDefaultUserNonEmptyCredGraph() {
        final HMACAuthenticator authenticator = createMockedAuthenticator();

        final Map<String, Object> configMap = new HashMap<String, Object>();
        configMap.put(CONFIG_CREDENTIALS_DB, "configCredDb");
        configMap.put(HMACAuthenticator.CONFIG_HMAC_SECRET, "secret");
        configMap.put(HMACAuthenticator.CONFIG_DEFAULT_PASSWORD, "pass");
        configMap.put(HMACAuthenticator.CONFIG_DEFAULT_USER, "user");

        final JanusGraph graph = createMock(JanusGraph.class);
        final CredentialTraversalSource credentialTraversalSource = createMock(CredentialTraversalSource.class);
        final ManagementSystem mgmt = createMock(ManagementSystem.class);
        final Transaction tx = createMock(Transaction.class);

        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        expect(authenticator.createCredentials(isA(JanusGraph.class))).andReturn(credentialTraversalSource);
        expect(mgmt.containsGraphIndex(eq("byUsername"))).andReturn(true);
        expect(graph.openManagement()).andReturn(mgmt);
        expect(graph.tx()).andReturn(tx);
        //expect(credentialTraversalSource.user("user")).andReturn(createMock(Vertex.class));
        tx.rollback();
        expectLastCall();

        replayAll();

        authenticator.setup(configMap);
    }

    @Test
    public void testAuthenticateBasicAuthValid() throws AuthenticationException {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        final String defaultUser = "user";
        final String defaultPassword = "pass";
        authenticator.setup(HmacConfigBuilder.build().defaultUser(defaultUser).defaultPassword(defaultPassword).create());
        final Map<String, String> credentials = CredentialsBuilder.build().user(defaultUser).password(defaultPassword).create();

        authenticator.authenticate(credentials);
    }

    @Test
    public void testAuthenticateBasicAuthInvalid() {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        final String defaultUser = "user";
        final String defaultPassword = "pass";
        authenticator.setup(HmacConfigBuilder.build().defaultUser(defaultUser).defaultPassword(defaultPassword).create());
        final Map<String, String> credentials = CredentialsBuilder.build().user(defaultUser).password("invalid").create();

        assertThrows(AuthenticationException.class, () -> authenticator.authenticate(credentials));
    }

    @Test
    public void testAuthenticateGenerateToken() throws AuthenticationException {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        final String defaultUser = "user";
        final String defaultPassword = "pass";
        authenticator.setup(HmacConfigBuilder.build().defaultUser(defaultUser).defaultUser(defaultPassword).create());
        final Map<String, String> credentials = CredentialsBuilder.build().
            user(defaultUser).
            password(defaultPassword).
            enableTokenGeneration().
            create();

        authenticator.authenticate(credentials);
        assertNotNull(credentials.get(PROPERTY_TOKEN));
    }

    @Test
    public void testAuthenticateWithToken() throws AuthenticationException {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        final String defaultUser = "user";
        String token = generateTokenForAuthenticatedUser(authenticator, defaultUser);

        AuthenticatedUser authenticatedUser =
            authenticator.authenticate(CredentialsBuilder.build().token(token).create());

        assertEquals(defaultUser, authenticatedUser.getName());
    }

    @Test
    public void testAuthenticateWithShortenedToken() throws AuthenticationException {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        String token = generateTokenForAuthenticatedUser(authenticator);
        final String brokenToken = token.substring(0, token.length() - 4);

        assertThrows(AuthenticationException.class,
            () -> authenticator.authenticate(CredentialsBuilder.build().token(brokenToken).create()));
    }

    @Test
    public void testAuthenticateWithBrokenToken() throws AuthenticationException {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        String token = generateTokenForAuthenticatedUser(authenticator);
        final String brokenToken = token.substring(0, token.length() - "abcdefgh".length()) + "abcdefgh";

        assertThrows(AuthenticationException.class,
            () -> authenticator.authenticate(CredentialsBuilder.build().token(brokenToken).create()));
    }

    @Test
    public void testAuthenticateWithTimedOutToken() throws AuthenticationException {
        final HMACAuthenticator authenticator = createMockedAuthenticator();
        final String defaultPassword = "pass";
        final String defaultUser = "user";
        ConfigBuilder.build().defaultUser(defaultUser).create();
        authenticator.setup(HmacConfigBuilder.build().tokenTimeout(1).defaultUser(defaultUser).defaultPassword(defaultPassword).create());
        final Map<String, String> credentials = CredentialsBuilder.build().
            user(defaultUser).
            password(defaultPassword).
            enableTokenGeneration().
            create();
        authenticator.authenticate(credentials);
        String token =  credentials.get(PROPERTY_TOKEN);

        assertThrows(AuthenticationException.class,
            () -> authenticator.authenticate(CredentialsBuilder.build().token(token).create()));
    }

    private String generateTokenForAuthenticatedUser(final HMACAuthenticator authenticator) throws AuthenticationException {
        return generateTokenForAuthenticatedUser(authenticator, "user");
    }

    private String generateTokenForAuthenticatedUser(final HMACAuthenticator authenticator, final String defaultUser) throws AuthenticationException {
        final String defaultPassword = "pass";
        ConfigBuilder.build().defaultUser(defaultUser).create();
        authenticator.setup(HmacConfigBuilder.build().defaultUser(defaultUser).defaultPassword(defaultPassword).create());
        final Map<String, String> credentials = CredentialsBuilder.build().
            user(defaultUser).
            password(defaultPassword).
            enableTokenGeneration().
            create();
        authenticator.authenticate(credentials);
        return credentials.get(PROPERTY_TOKEN);
    }

    private String authenticate(final HMACAuthenticator authenticator,
                                                     final Map<String, Object> config,
                                                     final Map<String, String> credentials) throws AuthenticationException {
        authenticator.setup(config);
        authenticator.authenticate(credentials);
        return credentials.get(PROPERTY_TOKEN);
    }

    private HMACAuthenticator createMockedAuthenticator() {
        final HMACAuthenticator authenticator =  createMockBuilder(HMACAuthenticator.class)
            .addMockedMethod("openGraph")
            .createMock();
        final JanusGraph graph = StorageSetup.getInMemoryGraph();
        expect(authenticator.openGraph(isA(String.class))).andReturn(graph);
        replayAll();
        return authenticator;
    }

    @Test
    public void testNewSaslNegotiatorOfInetAddr() {
        assertThrows(RuntimeException.class, () -> {
            final HMACAuthenticator authenticator = new HMACAuthenticator();
            authenticator.newSaslNegotiator(createMock(InetAddress.class));
        });
    }

    @Test
    public void testNewSaslNegotiator() {
        assertThrows(RuntimeException.class, () -> {
            final HMACAuthenticator authenticator = new HMACAuthenticator();
            authenticator.newSaslNegotiator();
        });
    }
}

class HmacConfigBuilder extends ConfigBuilder {
    public HmacConfigBuilder() {
        super();
        config.put(HMACAuthenticator.CONFIG_HMAC_SECRET, "secret");
    }

    public ConfigBuilder tokenTimeout(int timeout) {
        config.put(HMACAuthenticator.CONFIG_TOKEN_TIMEOUT, timeout);
        return this;
    }

    public static HmacConfigBuilder build() {
        return new HmacConfigBuilder();
    }
}
