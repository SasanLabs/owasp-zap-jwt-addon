/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.jwt.fuzzer;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocation;
import org.zaproxy.zap.model.MessageLocation;

/** @author preetkaran20@gmail.com */
public class JWTFuzzerHandler extends HttpFuzzerHandler {

    protected Class<? extends MessageLocation> getMessageLocationClass() {
        return JWTMessageLocation.class;
    }

    protected String createFuzzerName(HttpMessage message) {
        String uri = message.getRequestHeader().getURI().toString();
        if (uri.length() > 30) {
            uri = uri.substring(0, 14) + ".." + uri.substring(uri.length() - 15, uri.length());
        }
        return Constant.messages.getString("fuzz.httpfuzzer.fuzzerNamePrefix", uri);
    }

    public <T1 extends HttpFuzzerMessageProcessor, T2 extends HttpFuzzerMessageProcessorUI<T1>>
            void addFuzzerMessageProcessorUIHandler(
                    HttpFuzzerMessageProcessorUIHandler<T1, T2> processorUIHandler) {
        super.addFuzzerMessageProcessorUIHandler(processorUIHandler);
    }
}
