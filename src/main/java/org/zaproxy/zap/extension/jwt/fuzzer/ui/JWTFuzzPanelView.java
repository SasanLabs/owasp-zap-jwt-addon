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
package org.zaproxy.zap.extension.jwt.fuzzer.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestStringHttpPanelViewModel;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.FuzzerJWTSignatureOperation;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocation;
import org.zaproxy.zap.extension.jwt.utils.JWTConstants;
import org.zaproxy.zap.model.HttpMessageLocation.Location;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlight;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlighter;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlightsManager;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducer;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListener;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListenerAdapter;
import org.zaproxy.zap.view.messagelocation.TextMessageLocationHighlightsManager;

/**
 * This class {@code JWTFuzzPanelView} is JWT Fuzzer View which is used for selecting {@code
 * JWTMessageLocation} which is used fuzzing the JWT token. it will parse the JWT and gives user a
 * way to fuzz header and payload Json object using various payload generators.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTFuzzPanelView
        implements HttpPanelView, MessageLocationProducer, MessageLocationHighlighter {

    private static final Logger LOGGER = Logger.getLogger(JWTFuzzPanelView.class);
    private static final String HEADER_COMPONENT_LABEL = "jwt.fuzzer.panel.jwtComponent.header";
    private static final String PAYLOAD_COMPONENT_LABEL = "jwt.fuzzer.panel.jwtComponent.payload";

    private MessageLocationProducerFocusListenerAdapter focusListenerAdapter;
    private JScrollPane contentScrollPane;
    private JPanel contentPanel;
    private JPanel fuzzerPanel;
    private JComboBox<String> jwtComboBox;
    private JComboBox<String> jwtComponentType;
    private JComboBox<String> jwtComponentJsonKeysComboBox;
    private JComboBox<FuzzerJWTSignatureOperation> jwtSignatureOperationCheckBox;

    private GridBagConstraints gridBagConstraints;
    private Vector<String> jwtComboBoxModel =
            new Vector<String>(
                    Arrays.asList(JWTI18n.getMessage("jwt.fuzzer.panel.jwtcombobox.select")));
    private HttpMessage message;
    private Map<String, String> comboBoxKeyAndJwtMap = new HashMap<>();
    private Map<JWTMessageLocation, List<Component>> jwtMessageLocationAndRelatedComponentsMap =
            new HashMap<>();
    private ViewComponent viewComponent;

    public JWTFuzzPanelView() {
        this(null);
    }

    public JWTFuzzPanelView(ViewComponent viewComponent) {
        contentPanel = new JPanel();
        contentPanel.setSize(contentPanel.getPreferredSize());
        contentPanel.setLayout(new BorderLayout());
        fuzzerPanel = new JPanel();
        fuzzerPanel.setSize(fuzzerPanel.getPreferredSize());
        fuzzerPanel.setFocusable(true);
        GridBagLayout gridBagLayout = new GridBagLayout();
        fuzzerPanel.setLayout(gridBagLayout);
        contentScrollPane =
                new JScrollPane(
                        contentPanel,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        gridBagConstraints = this.getGridBagConstraints();
        init();
        contentPanel.add(fuzzerPanel, BorderLayout.NORTH);
        this.viewComponent = viewComponent;
    }

    private GridBagConstraints getGridBagConstraints() {
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;
        return gridBagConstraints;
    }

    private void init() {
        addLabel();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy++;
        addJWTMessageLocationSelectionUISection();
    }

    private void addLabel() {
        gridBagConstraints.gridx = 0;
        fuzzerPanel.add(
                new JLabel(JWTI18n.getMessage("jwt.settings.title"), JLabel.CENTER),
                gridBagConstraints);
        gridBagConstraints.gridx++;
        fuzzerPanel.add(
                new JLabel(JWTI18n.getMessage("jwt.fuzzer.panel.token.component"), JLabel.CENTER),
                gridBagConstraints);
        gridBagConstraints.gridx++;
        JLabel keyLabel =
                new JLabel(JWTI18n.getMessage("jwt.fuzzer.panel.token.key"), JLabel.CENTER);
        keyLabel.setPreferredSize(new Dimension(100, keyLabel.getHeight()));
        fuzzerPanel.add(keyLabel, gridBagConstraints);
        gridBagConstraints.gridx++;
        fuzzerPanel.add(
                new JLabel(
                        JWTI18n.getMessage("jwt.fuzzer.panel.signature.operationtype"),
                        JLabel.CENTER),
                gridBagConstraints);
    }

    private void addFuzzerFieldsActionListeners() {
        this.jwtComboBox.addActionListener((e) -> fuzzerPanel.requestFocusInWindow());
        this.jwtComponentJsonKeysComboBox.addActionListener(
                (e) -> fuzzerPanel.requestFocusInWindow());
        this.jwtComponentType.addActionListener((e) -> fuzzerPanel.requestFocusInWindow());
        this.jwtSignatureOperationCheckBox.addActionListener(
                (e) -> fuzzerPanel.requestFocusInWindow());
    }

    private void resetCurrentJWTMessageLocationUI() {
        if (jwtComponentJsonKeysComboBox != null) {
            jwtComponentJsonKeysComboBox.removeAllItems();
            fuzzerPanel.remove(jwtComponentJsonKeysComboBox);
        }

        if (jwtComponentType != null) {
            jwtComponentType.removeAllItems();
            fuzzerPanel.remove(jwtComponentType);
        }

        if (jwtSignatureOperationCheckBox != null) {
            fuzzerPanel.remove(jwtSignatureOperationCheckBox);
        }
    }

    private ActionListener getJWTComponentTypeActionListener(JWTHolder jwtHolder) {
        return (e) -> {
            String handle = jwtHolder.getHeader();
            if (jwtComponentType.getSelectedIndex() == 1) {
                handle = jwtHolder.getPayload();
            }
            JSONObject jsonObject = new JSONObject(handle);
            Vector<String> keys = new Vector<>();
            keys.addAll(jsonObject.keySet());
            jwtComponentJsonKeysComboBox.removeAllItems();
            for (String key : keys) {
                jwtComponentJsonKeysComboBox.addItem(key);
            }
            jwtComponentJsonKeysComboBox.setSelectedIndex(0);
            fuzzerPanel.revalidate();
        };
    }

    private void addJWTMessageLocationSelectionUISection() {
        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        jwtComboBox = new JComboBox<String>(this.jwtComboBoxModel);
        jwtComponentType = new JComboBox<String>();
        jwtComponentJsonKeysComboBox = new JComboBox<String>();
        jwtSignatureOperationCheckBox =
                new JComboBox<FuzzerJWTSignatureOperation>(FuzzerJWTSignatureOperation.values());
        this.addFuzzerFieldsActionListeners();
        fuzzerPanel.add(jwtComboBox, gridBagConstraints);
        jwtComboBox.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        if (jwtComboBox.getSelectedIndex() > 0) {
                            String selectedItem =
                                    comboBoxKeyAndJwtMap.get(
                                            jwtComboBox.getSelectedItem().toString());
                            try {
                                JWTHolder jwtHolder = JWTHolder.parseJWTToken(selectedItem);
                                jwtComponentType.removeAllItems();
                                ;
                                jwtComponentType.addItem(
                                        JWTI18n.getMessage(HEADER_COMPONENT_LABEL));
                                if (isValidJson(jwtHolder.getPayload())) {
                                    jwtComponentType.addItem(
                                            JWTI18n.getMessage(PAYLOAD_COMPONENT_LABEL));
                                }
                                jwtComponentType.setSelectedIndex(0);
                                gridBagConstraints.gridx++;
                                fuzzerPanel.add(jwtComponentType, gridBagConstraints);
                                gridBagConstraints.gridx++;
                                fuzzerPanel.add(jwtComponentJsonKeysComboBox, gridBagConstraints);
                                gridBagConstraints.gridx++;
                                fuzzerPanel.add(jwtSignatureOperationCheckBox, gridBagConstraints);
                                gridBagConstraints.gridx = 0;
                                String jwtComponentValue = jwtHolder.getHeader();
                                if (jwtComponentType.getSelectedIndex() == 1) {
                                    jwtComponentValue = jwtHolder.getPayload();
                                }
                                JSONObject jsonObject = new JSONObject(jwtComponentValue);
                                Vector<String> keys = new Vector<>();
                                keys.addAll(jsonObject.keySet());
                                jwtComponentJsonKeysComboBox.removeAllItems();
                                for (String key : keys) {
                                    jwtComponentJsonKeysComboBox.addItem(key);
                                }
                                jwtComponentJsonKeysComboBox.setSelectedIndex(0);
                                fuzzerPanel.revalidate();
                                jwtComponentType.addActionListener(
                                        getJWTComponentTypeActionListener(jwtHolder));
                            } catch (Exception e) {
                                LOGGER.error("Error Occurred: ", e);
                            }
                        } else {
                            resetCurrentJWTMessageLocationUI();
                        }
                        fuzzerPanel.revalidate();
                    }
                });
        fuzzerPanel.revalidate();
    }

    @Override
    public String getName() {
        return JWTI18n.getMessage("jwt.settings.title");
    }

    @Override
    public String getCaptionName() {
        return JWTI18n.getMessage("jwt.settings.title");
    }

    @Override
    public String getTargetViewName() {
        return null;
    }

    @Override
    public int getPosition() {
        return 0;
    }

    @Override
    public JComponent getPane() {
        return contentScrollPane;
    }

    @Override
    public void setSelected(boolean selected) {
        if (selected) {
            this.fuzzerPanel.requestFocusInWindow();
        }
    }

    @Override
    public void save() {}

    @Override
    public HttpPanelViewModel getModel() {
        return new RequestStringHttpPanelViewModel();
    }

    private boolean isValidJson(String value) {
        try {
            new JSONObject(value);
        } catch (JSONException ex) {
            return false;
        }
        return true;
    }

    public void populateJWTTokens(String httpMessageString) {
        Matcher matcher = JWTConstants.JWT_TOKEN_REGEX_FIND_PATTERN.matcher(httpMessageString);
        while (matcher.find()) {
            String jwtToken = matcher.group().trim();
            String key = jwtToken;
            try {
                JWTHolder jwtHolder = JWTHolder.parseJWTToken(key);
                // As Header of JWT is always JSON so header component should be a valid JSON Object
                // for the token to qualify
                // as valid JWT.
                if (isValidJson(jwtHolder.getHeader())) {
                    if (key.length() > 30) {
                        key = jwtToken.substring(0, 30);
                    }
                    comboBoxKeyAndJwtMap.put(key.concat("..."), jwtToken);
                }
            } catch (Exception e) {
                LOGGER.debug("Not a valid JWT Token", e);
            }
        }
    }

    public void setMessage(Message message) {
        if (viewComponent == ViewComponent.HEADER) {
            this.populateJWTTokens(this.message.getRequestHeader().toString());
        } else if (viewComponent == ViewComponent.BODY) {
            this.populateJWTTokens(this.message.getRequestBody().toString());
        } else {
            this.populateJWTTokens(this.message.getRequestHeader().toString());
            this.populateJWTTokens(this.message.getRequestBody().toString());
        }
        Set<String> jwtTokens = this.comboBoxKeyAndJwtMap.keySet();
        for (String jwtToken : jwtTokens) {
            if (!jwtComboBoxModel.contains(jwtToken)) {
                jwtComboBoxModel.addElement(jwtToken);
            }
        }
        this.fuzzerPanel.revalidate();
    }

    @Override
    public boolean isEnabled(Message message) {
        if (message != null) {
            this.message = (HttpMessage) message;
            setMessage(message);
            if (jwtComboBox.getItemCount() > 1) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasChanged() {
        return true;
    }

    @Override
    public boolean isEditable() {
        return true;
    }

    @Override
    public void setEditable(boolean editable) {}

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration configuration) {}

    @Override
    public void saveConfiguration(FileConfiguration configuration) {}

    @Override
    public MessageLocation getSelection() {
        Location location;
        String jwt = comboBoxKeyAndJwtMap.get(jwtComboBox.getSelectedItem().toString());
        String jwtComponentJsonKey = this.jwtComponentJsonKeysComboBox.getSelectedItem().toString();
        boolean isHeaderComponent =
                this.jwtComponentType
                        .getSelectedItem()
                        .equals(JWTI18n.getMessage(HEADER_COMPONENT_LABEL));
        int startIndex = this.message.getRequestHeader().toString().indexOf(jwt);
        if (startIndex >= 0) {
            location = Location.REQUEST_HEADER;
        } else {
            location = Location.REQUEST_BODY;
        }

        if (startIndex < 0) {
            startIndex = this.message.getRequestBody().toString().indexOf(jwt);
        }
        JWTMessageLocation jwtMessageLocation =
                new JWTMessageLocation(
                        location,
                        startIndex,
                        startIndex + jwt.length() - 1,
                        jwt,
                        jwtComponentJsonKey,
                        isHeaderComponent,
                        (FuzzerJWTSignatureOperation)
                                (jwtSignatureOperationCheckBox.getSelectedItem()));
        List<Component> components =
                Arrays.asList(
                        this.jwtComboBox,
                        this.jwtComponentType,
                        this.jwtComponentJsonKeysComboBox,
                        this.jwtSignatureOperationCheckBox);
        this.jwtMessageLocationAndRelatedComponentsMap.put(jwtMessageLocation, components);
        return jwtMessageLocation;
    }

    private Supplier<Boolean> getFocusListenerCriteria() {
        return () -> {
            if (this.jwtComboBox.getSelectedIndex() < 0) {
                return false;
            }

            if (this.jwtSignatureOperationCheckBox
                    .getSelectedItem()
                    .equals(FuzzerJWTSignatureOperation.NEW_SIGNATURE)) {
                JWTHolder jwtHolder;
                try {
                    String jwt = comboBoxKeyAndJwtMap.get(jwtComboBox.getSelectedItem().toString());
                    jwtHolder = JWTHolder.parseJWTToken(jwt);
                    if ((JWTConstants.JWT_HMAC_ALGO_TO_JAVA_ALGORITHM_MAPPING.containsKey(
                                    jwtHolder.getAlgorithm())
                            /* && JWTConfiguration.getInstance().getPassword().length == 0*/ )
                            || (jwtHolder
                                            .getAlgorithm()
                                            .startsWith(JWTConstants.JWT_RSA_ALGORITHM_IDENTIFIER)
                                    || jwtHolder
                                            .getAlgorithm()
                                            .startsWith(
                                                    JWTConstants.JWT_RSA_PSS_ALGORITHM_IDENTIFIER))
                    /* && this.jwtRsaSignatureFileChooserPath.length() == 0*/ ) {
                        return false;
                    }
                } catch (JWTException e) {
                    LOGGER.debug("Exception occurred: ", e);
                    return false;
                }
            }
            return true;
        };
    }

    @Override
    public void addFocusListener(MessageLocationProducerFocusListener focusListener) {
        getFocusListenerAdapter().addFocusListener(focusListener);
    }

    @Override
    public void removeFocusListener(MessageLocationProducerFocusListener focusListener) {
        getFocusListenerAdapter().removeFocusListener(focusListener);

        if (!getFocusListenerAdapter().hasFocusListeners()) {
            focusListenerAdapter = null;
        }
    }

    private MessageLocationProducerFocusListenerAdapter getFocusListenerAdapter() {
        if (focusListenerAdapter == null) {
            focusListenerAdapter =
                    new GenericCriteriaBasedMessageLocationProducerFocusListenerAdapter(
                            this, getFocusListenerCriteria());
            fuzzerPanel.addFocusListener(focusListenerAdapter);
        }
        return focusListenerAdapter;
    }

    @Override
    public MessageLocationHighlight highlight(MessageLocation location) {
        this.jwtMessageLocationAndRelatedComponentsMap
                .get(location)
                .forEach((component) -> component.setEnabled(false));
        addJWTMessageLocationSelectionUISection();
        return null;
    }

    @Override
    public MessageLocationHighlight highlight(
            MessageLocation location, MessageLocationHighlight highlight) {
        if (jwtMessageLocationAndRelatedComponentsMap.containsKey(location)) {
            this.jwtMessageLocationAndRelatedComponentsMap
                    .get(location)
                    .forEach((component) -> component.setEnabled(false));
        }
        addJWTMessageLocationSelectionUISection();
        return highlight;
    }

    @Override
    public void removeHighlight(
            MessageLocation location, MessageLocationHighlight highlightReference) {
        if (jwtMessageLocationAndRelatedComponentsMap.containsKey(location)) {
            this.jwtMessageLocationAndRelatedComponentsMap
                    .get(location)
                    .forEach((component) -> fuzzerPanel.remove(component));
        }
        fuzzerPanel.revalidate();
        this.jwtMessageLocationAndRelatedComponentsMap.remove((JWTMessageLocation) location);
    }

    @Override
    public Class<? extends MessageLocation> getMessageLocationClass() {
        return JWTMessageLocation.class;
    }

    @Override
    public MessageLocationHighlightsManager create() {
        return new TextMessageLocationHighlightsManager();
    }

    @Override
    public boolean supports(MessageLocation location) {
        return location instanceof JWTMessageLocation;
    }

    @Override
    public boolean supports(Class<? extends MessageLocation> classLocation) {
        return JWTMessageLocation.class.isAssignableFrom(classLocation);
    }
}
