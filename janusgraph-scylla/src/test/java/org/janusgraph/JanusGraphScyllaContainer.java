// Copyright 2020 JanusGraph Authors
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

package org.janusgraph;

import org.janusgraph.diskstorage.configuration.ModifiableConfiguration;
import org.testcontainers.containers.CassandraContainer;

import java.time.Duration;

import static org.janusgraph.diskstorage.cql.CQLConfigOptions.KEYSPACE;
import static org.janusgraph.diskstorage.cql.CQLConfigOptions.REMOTE_MAX_REQUESTS_PER_CONNECTION;
import static org.janusgraph.graphdb.configuration.GraphDatabaseConfiguration.*;

public class JanusGraphScyllaContainer extends CassandraContainer<JanusGraphScyllaContainer> {

    public JanusGraphScyllaContainer() {
        super("scylladb/scylla:latest");
    }

    public ModifiableConfiguration getConfiguration(final String keyspace) {
        final ModifiableConfiguration config = buildGraphConfiguration();
        config.set(KEYSPACE, keyspace);
        config.set(PAGE_SIZE, 500);
        config.set(CONNECTION_TIMEOUT, Duration.ofSeconds(60L));
        config.set(STORAGE_BACKEND, "scylla");
        config.set(STORAGE_PORT, getMappedPort(CQL_PORT));
        config.set(STORAGE_HOSTS, new String[]{getContainerIpAddress()});
        config.set(DROP_ON_CLEAR, false);
        config.set(REMOTE_MAX_REQUESTS_PER_CONNECTION, 1024);
        return config;
    }
}
