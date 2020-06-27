/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ExtensionHttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocationReplacerFactory;
import org.zaproxy.zap.extension.jwt.fuzzer.ui.JWTFuzzPanelViewFactory;
import org.zaproxy.zap.extension.jwt.ui.JWTOptionsPanel;
import org.zaproxy.zap.view.HttpPanelManager;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTExtension extends ExtensionAdaptor {

    protected static final Logger LOGGER = Logger.getLogger(JWTExtension.class);
    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionHttpFuzzer.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private HttpFuzzerHandler httpFuzzerHandler;
    private JWTMessageLocationReplacerFactory jwtMessageLocationReplacerFactory;

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getAuthor() {
        return "KSASAN preetkaran20@gmail.com";
    }

    @Override
    public void init() {
        JWTI18n.init();
        jwtMessageLocationReplacerFactory = new JWTMessageLocationReplacerFactory();
        MessageLocationReplacers.getInstance()
                .addReplacer(HttpMessage.class, jwtMessageLocationReplacerFactory);
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        HttpPanelManager panelManager = HttpPanelManager.getInstance();
        panelManager.addRequestViewFactory(
                RequestAllComponent.NAME, new JWTFuzzPanelViewFactory(null));
        panelManager.addRequestViewFactory(
                RequestSplitComponent.NAME, new JWTFuzzPanelViewFactory(ViewComponent.HEADER));
        panelManager.addRequestViewFactory(
                RequestSplitComponent.NAME, new JWTFuzzPanelViewFactory(ViewComponent.BODY));
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        try {
            extensionHook.addOptionsParamSet(getJWTConfiguration());
            extensionHook.getHookView().addOptionPanel(new JWTOptionsPanel());
            ExtensionFuzz extensionFuzz =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
            extensionFuzz.addFuzzerHandler(httpFuzzerHandler);
            LOGGER.debug("JWT Extension loaded successfully");
        } catch (Exception e) {
            LOGGER.error("JWT Extension can't be loaded. Configuration not found or invalid", e);
        }
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

    private JWTConfiguration getJWTConfiguration() {
        return JWTConfiguration.getInstance();
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
