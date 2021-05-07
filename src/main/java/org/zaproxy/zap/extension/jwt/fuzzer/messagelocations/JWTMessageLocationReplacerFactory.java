/**
 * Copyright 2021 SasanLabs
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.jwt.fuzzer.messagelocations;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacerFactory;
import org.zaproxy.zap.model.MessageLocation;

/**
 * {@code JWTMessageLocationReplacerFactory} provides the instance of {@link
 * JWTMessageLocationReplacer}
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTMessageLocationReplacerFactory
        implements MessageLocationReplacerFactory<HttpMessage> {

    @Override
    public Class<? extends MessageLocation> getTargetMessageLocation() {
        return JWTMessageLocation.class;
    }

    @Override
    public MessageLocationReplacer<HttpMessage> createReplacer() {
        return new JWTMessageLocationReplacer();
    }
}
