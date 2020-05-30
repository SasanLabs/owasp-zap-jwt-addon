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
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocationReplacerFactory;
import org.zaproxy.zap.extension.jwt.fuzzer.ui.JWTFuzzPanelViewFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.view.HttpPanelManager;

public class ExtensionJWTFuzzer extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    private JWTFuzzerHandler jwtFuzzerHandler;
    private JWTMessageLocationReplacerFactory jwtMessageLocationReplacerFactory;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionFuzz.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionJWTFuzzer() {
        super();
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("fuzz.httpfuzzer.description");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void init() {
        jwtFuzzerHandler = new JWTFuzzerHandler();
        jwtMessageLocationReplacerFactory = new JWTMessageLocationReplacerFactory();
        MessageLocationReplacers.getInstance()
                .addReplacer(HttpMessage.class, jwtMessageLocationReplacerFactory);
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        HttpPanelManager panelManager = HttpPanelManager.getInstance();
        panelManager.addRequestViewFactory(
                RequestAllComponent.NAME, new JWTFuzzPanelViewFactory(null));
        panelManager.addRequestViewFactory(
                RequestSplitComponent.NAME, new JWTFuzzPanelViewFactory(ViewComponent.HEADER));
        panelManager.addRequestViewFactory(
                RequestSplitComponent.NAME, new JWTFuzzPanelViewFactory(ViewComponent.BODY));

        if (extensionScript != null) {
            jwtFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new FuzzerHttpMessageScriptProcessorAdapterUIHandler(extensionScript));
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        JWTI18n.init();
        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        extensionFuzz.addFuzzerHandler(jwtFuzzerHandler);
        extensionHook
                .getHookMenu()
                .addPopupMenuItem(new JWTFuzzAttackPopupMenuItem(extensionFuzz, jwtFuzzerHandler));
    }

    @Override
    public void unload() {
        super.unload();
        HttpPanelManager panelManager = HttpPanelManager.getInstance();
        panelManager.removeRequestViewFactory(
                RequestAllComponent.NAME, new JWTFuzzPanelViewFactory(null).getName());
        panelManager.removeRequestViewFactory(
                RequestSplitComponent.NAME,
                new JWTFuzzPanelViewFactory(ViewComponent.HEADER).getName());
        panelManager.removeRequestViewFactory(
                RequestSplitComponent.NAME,
                new JWTFuzzPanelViewFactory(ViewComponent.BODY).getName());
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
