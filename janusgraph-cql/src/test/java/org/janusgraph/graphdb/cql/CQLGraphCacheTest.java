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

package org.janusgraph.graphdb.cql;

import io.github.artsok.ParameterizedRepeatedIfExceptionsTest;
import io.github.artsok.RepeatedIfExceptionsTest;
import org.janusgraph.JanusGraphCassandraContainer;
import org.janusgraph.StorageSetup;
import org.janusgraph.diskstorage.configuration.WriteConfiguration;
import org.janusgraph.graphdb.JanusGraphTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.concurrent.ExecutionException;

@Testcontainers
public class CQLGraphCacheTest extends JanusGraphTest {

    @Container
    public static final JanusGraphCassandraContainer cqlContainer = new JanusGraphCassandraContainer();

    @Override
    public WriteConfiguration getConfiguration() {
        return StorageSetup.addPermanentCache(cqlContainer.getConfiguration(getClass().getSimpleName()));
    }

    @ParameterizedRepeatedIfExceptionsTest(repeats = 4, minSuccess = 2)
    @ValueSource(booleans = {true, false})
    public void simpleLogTest(boolean useStringId) throws InterruptedException {
        super.simpleLogTest(useStringId);
    }

    @ParameterizedRepeatedIfExceptionsTest(repeats = 4, minSuccess = 2)
    @ValueSource(booleans = {true, false})
    public void simpleLogTestWithFailure(boolean useStringId) throws InterruptedException {
        super.simpleLogTestWithFailure(useStringId);
    }

    @RepeatedIfExceptionsTest(repeats = 4, minSuccess = 2)
    @Override
    public void testEdgeTTLTiming() throws Exception {
        super.testEdgeTTLTiming();
    }

    @RepeatedIfExceptionsTest(repeats = 4, minSuccess = 2)
    @Override
    public void testEdgeTTLWithTransactions() throws Exception {
        super.testEdgeTTLWithTransactions();
    }

    @RepeatedIfExceptionsTest(repeats = 4, minSuccess = 2)
    @Override
    public void testVertexTTLWithCompositeIndex() throws Exception {
        super.testVertexTTLWithCompositeIndex();
    }

    @RepeatedIfExceptionsTest(repeats = 4, minSuccess = 2)
    @Override
    public void testVertexTTLImplicitKey() throws Exception {
        super.testVertexTTLImplicitKey();
    }

    @RepeatedIfExceptionsTest(repeats = 3)
    @Override
    public void testReindexingForEdgeIndex() throws ExecutionException, InterruptedException {
        super.testReindexingForEdgeIndex();
    }
}
