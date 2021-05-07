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

import java.awt.Component;
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
import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestStringHttpPanelViewModel;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.FuzzerJWTSignatureOperation;
import org.zaproxy.zap.extension.jwt.fuzzer.messagelocations.JWTMessageLocation;
import org.zaproxy.zap.extension.jwt.utils.JWTConstants;
import org.zaproxy.zap.extension.jwt.utils.JWTUIUtils;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
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
 * JWTMessageLocation} which is used for fuzzing the JWT. it will parse the JWT and gives user a way
 * to fuzz header and payload Json object using various payload generators.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTFuzzPanelView
        implements HttpPanelView, MessageLocationProducer, MessageLocationHighlighter {

    private static final Logger LOGGER = Logger.getLogger(JWTFuzzPanelView.class);
    public static final String NAME = "JWTFuzzPanelView";
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
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentScrollPane =
                new JScrollPane(
                        contentPanel,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        contentPanel.add(this.getJWTCommonConfigurationPanel());
        contentPanel.add(this.getFuzzerPanel());
        this.viewComponent = viewComponent;
    }

    private JPanel getJWTCommonConfigurationPanel() {
        JPanel commonPropertiesPanel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        commonPropertiesPanel.setLayout(gridBagLayout);
        commonPropertiesPanel.setBorder(
                JWTUIUtils.getTitledBorder("jwt.fuzzer.panel.commonConfiguration"));
        GridBagConstraints gridBagConstraints = JWTUIUtils.getGridBagConstraints();
        gridBagConstraints.gridx = 0;
        commonPropertiesPanel.add(
                new JLabel(JWTI18n.getMessage("jwt.settings.title"), JLabel.CENTER),
                gridBagConstraints);
        gridBagConstraints.gridx++;
        commonPropertiesPanel.add(
                new JLabel(
                        JWTI18n.getMessage("jwt.fuzzer.panel.signature.operationtype"),
                        JLabel.CENTER),
                gridBagConstraints);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy++;
        jwtComboBox = new JComboBox<String>(this.jwtComboBoxModel);
        commonPropertiesPanel.add(jwtComboBox, gridBagConstraints);
        gridBagConstraints.gridx++;
        jwtSignatureOperationCheckBox =
                new JComboBox<FuzzerJWTSignatureOperation>(FuzzerJWTSignatureOperation.values());
        commonPropertiesPanel.add(jwtSignatureOperationCheckBox, gridBagConstraints);
        this.addActionListenerToRequestFocus(this.jwtComboBox);
        this.addActionListenerToRequestFocus(this.jwtSignatureOperationCheckBox);
        return commonPropertiesPanel;
    }

    private <T> void addActionListenerToRequestFocus(JComboBox<T> comboBox) {
        comboBox.addActionListener((e) -> contentPanel.requestFocusInWindow());
    }

    private JPanel getFuzzerPanel() {
        fuzzerPanel = new JPanel();
        fuzzerPanel.setBorder(JWTUIUtils.getTitledBorder("jwt.fuzzer.panel.jwtProperties"));
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagConstraints = JWTUIUtils.getGridBagConstraints();
        fuzzerPanel.setLayout(gridBagLayout);

        JLabel componentLabel =
                new JLabel(JWTI18n.getMessage("jwt.fuzzer.panel.token.component"), JLabel.CENTER);
        fuzzerPanel.add(componentLabel, gridBagConstraints);
        gridBagConstraints.gridx++;
        JLabel keyLabel =
                new JLabel(JWTI18n.getMessage("jwt.fuzzer.panel.token.key"), JLabel.CENTER);
        fuzzerPanel.add(keyLabel, gridBagConstraints);

        gridBagConstraints.gridy++;
        addActionListenerOnJWTComboBox();
        return fuzzerPanel;
    }

    private void updateUIWithJWTSelection() {
        if (jwtComboBox.getSelectedIndex() > 0) {
            jwtComponentType = new JComboBox<String>();
            jwtComponentJsonKeysComboBox = new JComboBox<String>();
            this.addActionListenerToRequestFocus(jwtComponentType);
            this.addActionListenerToRequestFocus(jwtComponentJsonKeysComboBox);
            String selectedItem =
                    comboBoxKeyAndJwtMap.get(jwtComboBox.getSelectedItem().toString());
            try {
                JWTHolder jwtHolder = JWTHolder.parseJWTToken(selectedItem);
                jwtComponentType.addItem(JWTI18n.getMessage(HEADER_COMPONENT_LABEL));
                if (JWTUtils.isValidJson(jwtHolder.getPayload())) {
                    jwtComponentType.addItem(JWTI18n.getMessage(PAYLOAD_COMPONENT_LABEL));
                }
                jwtComponentType.setSelectedIndex(0);
                gridBagConstraints.gridx = 0;
                fuzzerPanel.add(jwtComponentType, gridBagConstraints);
                gridBagConstraints.gridx++;
                fuzzerPanel.add(jwtComponentJsonKeysComboBox, gridBagConstraints);

                String jwtComponentValue = jwtHolder.getHeader();
                if (jwtComponentType.getSelectedIndex() == 1) {
                    jwtComponentValue = jwtHolder.getPayload();
                }
                JSONObject jsonObject = new JSONObject(jwtComponentValue);
                Vector<String> keys = new Vector<>();
                keys.addAll(jsonObject.keySet());
                for (String key : keys) {
                    jwtComponentJsonKeysComboBox.addItem(key);
                }
                jwtComponentJsonKeysComboBox.setSelectedIndex(0);
                jwtComponentType.addActionListener(getJWTComponentTypeActionListener(jwtHolder));
            } catch (Exception e) {
                LOGGER.error("Error Occurred: ", e);
            }
        } else {
            resetFuzzerPanelSection();
        }
        fuzzerPanel.revalidate();
    }

    private void resetFuzzerPanelSection() {
        if (jwtComponentJsonKeysComboBox != null) {
            jwtComponentJsonKeysComboBox.removeAllItems();
            fuzzerPanel.remove(jwtComponentJsonKeysComboBox);
        }

        if (jwtComponentType != null) {
            jwtComponentType.removeAllItems();
            fuzzerPanel.remove(jwtComponentType);
        }
    }

    private ActionListener getJWTComponentTypeActionListener(JWTHolder jwtHolder) {
        return (e) -> {
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
        };
    }

    private void addActionListenerOnJWTComboBox() {
        jwtComboBox.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        updateUIWithJWTSelection();
                    }
                });
    }

    /** Adds the New JWT Component Type and Key Field ComboBox. */
    private void addNewFuzzerFieldsRow() {
        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        updateUIWithJWTSelection();
    }

    @Override
    public String getName() {
        return this.viewComponent != null ? NAME + this.viewComponent : NAME;
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
            this.contentPanel.requestFocusInWindow();
        }
    }

    @Override
    public void save() {}

    @Override
    public HttpPanelViewModel getModel() {
        return new RequestStringHttpPanelViewModel();
    }

    public void populateJWTTokens(String httpMessageString) {
        Matcher matcher = JWTConstants.JWT_TOKEN_REGEX_PATTERN.matcher(httpMessageString);
        while (matcher.find()) {
            String jwtToken = matcher.group().trim();
            String key = jwtToken;
            try {
                JWTHolder jwtHolder = JWTHolder.parseJWTToken(key);
                // As Header of JWT is always JSON so header component should be a valid JSON Object
                // for the token to qualify
                // as valid JWT.
                if (JWTUtils.isValidJson(jwtHolder.getHeader())) {
                    if (key.length() > 30) {
                        key = jwtToken.substring(0, 30);
                    }
                    comboBoxKeyAndJwtMap.put(key.concat("..."), jwtToken);
                }
            } catch (Exception e) {
                LOGGER.debug("Not a valid JWT", e);
            }
        }
    }

    public void setMessage(Message message) {
        this.message = (HttpMessage) message;
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
            startIndex = this.message.getRequestBody().toString().indexOf(jwt);
        }
        JWTMessageLocation jwtMessageLocation =
                new JWTMessageLocation(
                        location,
                        startIndex,
                        startIndex + jwt.length(),
                        jwt,
                        jwtComponentJsonKey,
                        isHeaderComponent,
                        (FuzzerJWTSignatureOperation)
                                (jwtSignatureOperationCheckBox.getSelectedItem()));
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
                                    && JWTConfiguration.getInstance().getHMacSignatureKey() != null
                                    && JWTConfiguration.getInstance().getHMacSignatureKey().length
                                            == 0)
                            || (jwtHolder
                                                    .getAlgorithm()
                                                    .startsWith(
                                                            JWTConstants
                                                                    .JWT_RSA_ALGORITHM_IDENTIFIER)
                                            || jwtHolder
                                                    .getAlgorithm()
                                                    .startsWith(
                                                            JWTConstants
                                                                    .JWT_RSA_PSS_ALGORITHM_IDENTIFIER))
                                    && JWTConfiguration.getInstance()
                                                    .getRsaPrivateKeyFileChooserPath()
                                            != null
                                    && JWTConfiguration.getInstance()
                                                    .getRsaPrivateKeyFileChooserPath()
                                                    .length()
                                            == 0) {
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
            contentPanel.addFocusListener(focusListenerAdapter);
        }
        return focusListenerAdapter;
    }

    @Override
    public MessageLocationHighlight highlight(MessageLocation location) {
        return this.highlight(location, null);
    }

    @Override
    public MessageLocationHighlight highlight(
            MessageLocation location, MessageLocationHighlight highlight) {
        List<Component> components =
                Arrays.asList(this.jwtComponentType, this.jwtComponentJsonKeysComboBox);
        this.jwtMessageLocationAndRelatedComponentsMap.put(
                (JWTMessageLocation) location, components);
        components.forEach((component) -> component.setEnabled(false));
        addNewFuzzerFieldsRow();
        if (jwtMessageLocationAndRelatedComponentsMap.size() > 0) {
            this.jwtComboBox.setEnabled(false);
            this.jwtSignatureOperationCheckBox.setEnabled(false);
        }
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
        this.jwtMessageLocationAndRelatedComponentsMap.remove((JWTMessageLocation) location);
        if (jwtMessageLocationAndRelatedComponentsMap.size() == 0) {
            this.jwtComboBox.setEnabled(true);
            this.jwtSignatureOperationCheckBox.setEnabled(true);
        }
        fuzzerPanel.revalidate();
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
