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

import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandlerOptionsPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorCollection;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerOptions;
import org.zaproxy.zap.extension.fuzz.impl.FuzzerDialog;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacementGenerator;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsBreadthFirstReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsDepthFirstReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacer;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocation;
import org.zaproxy.zap.view.messagecontainer.SelectableContentMessageContainer;

/** @author preetkaran20@gmail.com */
public class JWTFuzzerHandler extends HttpFuzzerHandler {

    private final List<HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>>
            messageProcessors;

    public JWTFuzzerHandler() {
        this.messageProcessors = new ArrayList<>();
    }

    @Override
    public HttpFuzzer showFuzzerDialog(HttpMessage message, FuzzerOptions defaultOptions) {
        return showFuzzerDialogImpl(message, null, defaultOptions);
    }

    public HttpFuzzer showFuzzerDialogImpl(
            HttpMessage message,
            SelectableContentMessageContainer<HttpMessage> container,
            FuzzerOptions defaultOptions) {
        FuzzerDialog<HttpMessage, HttpFuzzerOptions, HttpFuzzerMessageProcessor> fuzzDialogue =
                new FuzzerDialog<>(
                        View.getSingleton().getMainFrame(),
                        defaultOptions,
                        message,
                        true,
                        new HttpFuzzerHandlerOptionsPanel(),
                        new HttpFuzzerMessageProcessorCollection(message, messageProcessors));

        if (container != null) {
            if (fuzzDialogue.setSelectedContainer(container.getName())) {
                fuzzDialogue.addMessageLocation(container.getSelection());
            }
        }

        fuzzDialogue.setVisible(true);
        fuzzDialogue.dispose();

        return createFuzzer(
                message,
                fuzzDialogue.getFuzzLocations(),
                fuzzDialogue.getFuzzerOptions(),
                fuzzDialogue.getFuzzerMessageProcessors());
    }

    @SuppressWarnings("unchecked")
    private HttpFuzzer createFuzzer(
            HttpMessage message,
            List<PayloadGeneratorMessageLocation<?>> fuzzLocations,
            HttpFuzzerOptions options,
            List<HttpFuzzerMessageProcessor> processors) {
        if (fuzzLocations.isEmpty()) {
            return null;
        }

        MessageLocationReplacer<HttpMessage> replacer =
                MessageLocationReplacers.getInstance()
                        .getMLR(HttpMessage.class, JWTMessageLocation.class);

        replacer.init(message);

        MultipleMessageLocationsReplacer<HttpMessage> multipleMessageLocationsReplacer;
        if (MessageLocationsReplacementStrategy.DEPTH_FIRST
                == options.getPayloadsReplacementStrategy()) {
            multipleMessageLocationsReplacer = new MultipleMessageLocationsDepthFirstReplacer<>();
        } else {
            multipleMessageLocationsReplacer = new MultipleMessageLocationsBreadthFirstReplacer<>();
        }
        SortedSet<MessageLocationReplacementGenerator<?, ?>> messageLocationReplacementGenerators =
                new TreeSet<>();

        for (PayloadGeneratorMessageLocation<?> fuzzLocation : fuzzLocations) {
            messageLocationReplacementGenerators.add(fuzzLocation);
        }
        multipleMessageLocationsReplacer.init(replacer, messageLocationReplacementGenerators);

        return new HttpFuzzer(
                createFuzzerName(message),
                options,
                message,
                (List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>)
                        (List) fuzzLocations,
                multipleMessageLocationsReplacer,
                processors);
    }

    private String createFuzzerName(HttpMessage message) {
        String uri = message.getRequestHeader().getURI().toString();
        if (uri.length() > 30) {
            uri = uri.substring(0, 14) + ".." + uri.substring(uri.length() - 15, uri.length());
        }
        return Constant.messages.getString("fuzz.httpfuzzer.fuzzerNamePrefix", uri);
    }

    @SuppressWarnings("unchecked")
    public <T1 extends HttpFuzzerMessageProcessor, T2 extends HttpFuzzerMessageProcessorUI<T1>>
            void addFuzzerMessageProcessorUIHandler(
                    HttpFuzzerMessageProcessorUIHandler<T1, T2> processorUIHandler) {
        messageProcessors.add(
                (HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>)
                        processorUIHandler);
    }

    protected <T1 extends HttpFuzzerMessageProcessor, T2 extends HttpFuzzerMessageProcessorUI<T1>>
            void removeFuzzerMessageProcessorUIHandler(
                    HttpFuzzerMessageProcessorUIHandler<T1, T2> processorUIHandler) {
        messageProcessors.remove(processorUIHandler);
    }
}
