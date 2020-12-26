/**
 * Copyright 2020 SasanLabs
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
import org.zaproxy.zap.extension.fuzz.MessagePanelManager;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ExtensionHttpFuzzer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocationReplacerFactory;
import org.zaproxy.zap.extension.jwt.fuzzer.ui.JWTFuzzPanelView;
import org.zaproxy.zap.extension.jwt.fuzzer.ui.JWTFuzzPanelViewFactory;
import org.zaproxy.zap.extension.jwt.ui.JWTOptionsPanel;

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
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        if (this.hasView()) {
            MessagePanelManager panelManager = extensionFuzz.getClientMessagePanelManager();
            panelManager.addViewFactory(
                    RequestAllComponent.NAME, new JWTFuzzPanelViewFactory(null));
            panelManager.addViewFactory(
                    RequestSplitComponent.NAME, new JWTFuzzPanelViewFactory(ViewComponent.HEADER));
            panelManager.addViewFactory(
                    RequestSplitComponent.NAME, new JWTFuzzPanelViewFactory(ViewComponent.BODY));
            extensionHook.getHookView().addOptionPanel(new JWTOptionsPanel());
        }
        extensionHook.addOptionsParamSet(getJWTConfiguration());
        LOGGER.debug("JWT Extension loaded successfully");
    }

    @Override
    public void unload() {
        super.unload();
        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        if (this.hasView()) {
            MessagePanelManager panelManager = extensionFuzz.getClientMessagePanelManager();
            panelManager.removeViewFactory(
                    RequestAllComponent.NAME, new JWTFuzzPanelViewFactory(null).getName());
            panelManager.removeViewFactory(
                    RequestSplitComponent.NAME,
                    new JWTFuzzPanelViewFactory(ViewComponent.HEADER).getName());
            panelManager.removeViewFactory(
                    RequestSplitComponent.NAME,
                    new JWTFuzzPanelViewFactory(ViewComponent.BODY).getName());
            panelManager.removeViews(RequestAllComponent.NAME, JWTFuzzPanelView.NAME, null);
            panelManager.removeViews(
                    RequestAllComponent.NAME,
                    JWTFuzzPanelView.NAME + ViewComponent.HEADER,
                    ViewComponent.HEADER);
            panelManager.removeViews(
                    RequestAllComponent.NAME,
                    JWTFuzzPanelView.NAME + ViewComponent.BODY,
                    ViewComponent.BODY);
        }
        MessageLocationReplacers.getInstance()
                .removeReplacer(HttpMessage.class, jwtMessageLocationReplacerFactory);
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
