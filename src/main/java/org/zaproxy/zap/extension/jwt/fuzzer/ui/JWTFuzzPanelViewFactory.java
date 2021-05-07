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
package org.zaproxy.zap.extension.jwt.fuzzer.ui;

import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

/**
 * {@code JWTFuzzPanelViewFactory} is used for creating {@link JWTFuzzPanelView} which is used for
 * representing the JWT present in the Request.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTFuzzPanelViewFactory implements HttpPanelViewFactory {

    private ViewComponent viewComponent;
    private static final String NAME = "JWTFuzzPanelViewFactory";

    /**
     * View Component is important for {@link RequestSplitComponent} to specify where to display the
     * view. i.e. in Header or Body component.
     *
     * @param viewComponent view component
     */
    public JWTFuzzPanelViewFactory(ViewComponent viewComponent) {
        this.viewComponent = viewComponent;
    }

    @Override
    public String getName() {
        return this.viewComponent != null ? NAME + this.viewComponent : NAME;
    }

    @Override
    public HttpPanelView getNewView() {
        return new JWTFuzzPanelView(viewComponent);
    }

    @Override
    public Object getOptions() {
        return viewComponent;
    }
}
