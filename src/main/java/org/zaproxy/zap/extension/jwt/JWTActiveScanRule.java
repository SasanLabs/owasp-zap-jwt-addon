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
package org.zaproxy.zap.extension.jwt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.jwt.attacks.ClientSideAttack;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;

/**
 * JWT Scanner is used to find the vulnerabilities in JWT implementations. <br>
 * Resources containing more information about vulnerabilities in implementations are: <br>
 *
 * <ol>
 *   <li><a href="https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-06" >JSON Web Token Best
 *       Practices(IETF document)</a>
 *   <li><a
 *       href="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html">
 *       OWASP cheatsheet for vulnerabilities in JWT implementation</a>
 *   <li><a href="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries">For
 *       server side vulnerabilities in JWT implementations</a>
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTActiveScanRule extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 40036;
    private static final String NAME = JWTI18n.getMessage("jwt.scanner.name");
    private static final String DESCRIPTION = JWTI18n.getMessage("jwt.scanner.description");
    private static final String SOLUTION = JWTI18n.getMessage("jwt.scanner.soln");
    private static final String REFERENCE = JWTI18n.getMessage("jwt.scanner.refs");
    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanRule.class);
    private static final String AUTHORIZATION_HEADER_KEY =
            HttpRequestHeader.AUTHORIZATION.toLowerCase(Locale.ROOT);
    private int maxRequestCount;

    @Override
    public void init() {
        switch (this.getAttackStrength()) {
            case LOW:
                maxRequestCount = 4;
                break;
            case MEDIUM:
                maxRequestCount = 8;
                break;
            case HIGH:
                maxRequestCount = 18;
                break;
            case INSANE:
                maxRequestCount = 28;
                break;
            default:
                maxRequestCount = 8;
                break;
        }
    }

    protected void scan(List<NameValuePair> nameValuePairs) {
        if (nameValuePairs.isEmpty()
                || nameValuePairs.get(0).getType() != NameValuePair.TYPE_HEADER) {
            super.scan(nameValuePairs);
        } else {
            nameValuePairs = new ArrayList<>(nameValuePairs);
            List<HttpHeaderField> headerFields = getBaseMsg().getRequestHeader().getHeaders();
            for (HttpHeaderField headerField : headerFields) {
                if (AUTHORIZATION_HEADER_KEY.equals(
                        headerField.getName().toLowerCase(Locale.ROOT))) {
                    nameValuePairs.add(
                            new NameValuePair(
                                    NameValuePair.TYPE_HEADER,
                                    headerField.getName(),
                                    headerField.getValue(),
                                    nameValuePairs.size()));
                    break;
                }
            }
            super.scan(nameValuePairs);
        }
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        String newValue = value.trim();
        newValue = JWTUtils.extractingJWTFromParamValue(newValue);

        if (!JWTUtils.isTokenValid(newValue)) {
            LOGGER.debug("Token: " + newValue + " is not a valid JWT token.");
            return;
        }
        // Sending request to save actual response and then compare it with new response
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.warn("Error occurred while sending the request", e);
            return;
        }

        JWTHolder jwtHolder;
        try {
            jwtHolder = JWTHolder.parseJWTToken(newValue);
        } catch (JWTException e) {
            LOGGER.debug("Unable to parse JWT Token", e);
            return;
        }

        if (JWTConfiguration.getInstance().isEnableClientConfigurationScan()) {
            performAttackClientSideConfigurations(msg, param);
            this.decreaseRequestCount();
        }
        performAttackServerSideConfigurations(msg, param, jwtHolder, value);
    }

    @Override
    public boolean isStop() {
        return super.isStop() || (this.maxRequestCount <= 0);
    }

    public void decreaseRequestCount() {
        this.maxRequestCount--;
    }

    /**
     * Performs attack to find if client side configuration for JWT token is proper.
     *
     * @param msg a copy of the HTTP message currently under scanning
     * @param param the name of the parameter under testing
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    private boolean performAttackClientSideConfigurations(HttpMessage msg, String param) {
        return new ClientSideAttack(this, param, msg).execute();
    }

    /**
     * Performs attack to find JWT implementation weaknesses like weak key usage or other types of
     * attacks.
     *
     * @param msg a copy of the HTTP message currently under scanning
     * @param param the name of the parameter under testing
     * @param jwtHolder is the parsed representation of JWT token
     * @param value the value of the parameter under testing
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    private boolean performAttackServerSideConfigurations(
            HttpMessage msg, String param, JWTHolder jwtHolder, String value) {

        return new ServerSideAttack(jwtHolder, this, param, msg, value).execute();
    }

    /**
     * TODO Not sure how can this be implemented. Waits some time to check if token is expired and
     * then execute the attack. TODO need to implement it.
     *
     * @param jwtHolder is the parsed representation of JWT token
     * @param msg a copy of the HTTP message currently under scanning
     * @param param the name of the parameter under testing
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    private boolean checkExpiredTokenAttack(JWTHolder jwtHolder, HttpMessage msg, String param) {
        return false;
    }

    public void raiseAlert(
            int risk,
            int confidence,
            String name,
            String description,
            String uri,
            String param,
            String attack,
            String otherInfo,
            String solution,
            HttpMessage msg) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setName(name)
                .setDescription(description)
                .setUri(uri)
                .setParam(param)
                .setAttack(attack)
                .setOtherInfo(otherInfo)
                .setSolution(solution)
                .setMessage(msg)
                .raise();
    }

    /**
     * @param msg a copy of the HTTP message currently under scanning
     * @param param the name of the parameter under testing
     * @param jwtToken manipulated value of the parameter under testing
     * @param value the value of the parameter under testing
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    public boolean sendManipulatedMsgAndCheckIfAttackSuccessful(
            HttpMessage msg, String param, String jwtToken, String value) {
        HttpMessage newMsg = this.getNewMsg();
        this.setParameter(newMsg, param, JWTUtils.addingJWTToParamValue(value, jwtToken));
        try {
            this.sendAndReceive(newMsg, false);
            if (newMsg.getResponseHeader().getStatusCode()
                            == msg.getResponseHeader().getStatusCode()
                    && newMsg.getResponseBody().equals(msg.getResponseBody())) {
                return true;
            }
        } catch (IOException e) {
            LOGGER.warn("Following exception occurred while sending manipulated jwt message", e);
        }
        return false;
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getSolution() {
        return SOLUTION;
    }

    @Override
    public String getReference() {
        return REFERENCE;
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }
}
