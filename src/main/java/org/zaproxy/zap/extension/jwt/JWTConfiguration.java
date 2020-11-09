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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;

/**
 * This class holds configuration related to JWT scanner.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTConfiguration extends VersionedAbstractParam {

    protected static final Logger LOGGER = Logger.getLogger(JWTExtension.class);

    /** The base configuration key for all JWT configurations. */
    private static final String PARAM_BASE_KEY = "jwt";

    private static final String CONFIG_VERSION_KEY = PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    private static final int CURRENT_CONFIG_VERSION = 1;
    private static final String PARAM_TRUST_STORE_PATH = PARAM_BASE_KEY + ".trustStorePath";
    private static final String PARAM_TRUST_STORE_PASSWORD = PARAM_BASE_KEY + ".trustStorePassword";
    private static final String PARAM_ENABLE_CLIENT_CONFIGURATION_SCAN =
            PARAM_BASE_KEY + ".enableClientConfigurationScan";

    private String trustStorePath;
    private String trustStorePassword;

    /** Fuzzer settings. Not storing private keys because of security concerns. */
    private String rsaPrivateKeyFileChooserPath;

    private char[] hmacSignatureKey;

    private boolean enableClientConfigurationScan;
    private static volatile JWTConfiguration jwtConfiguration;

    /**
     * Files containing publicly well known JWT HMac Secrets.
     *
     * <p>There are publicly available well known JWT HMac Secrets. Special thanks to <a href=
     * "https://lab.wallarm.com/340-weak-jwt-secrets-you-should-check-in-your-code/">Wallarm.com</a>
     * for collating the list of such weak secrets and making them open-source.
     */
    private static final List<String> FILE_NAMES_CONTAINING_PUBLICLY_KNOWN_HMAC_SECRETS =
            Arrays.asList("/weakKeys/wallarm_jwt_hmac_secrets_list");

    private Set<String> publiclyKnownHMacSecrets = new HashSet<>();

    private JWTConfiguration() {
        init();
    }

    private void init() {
        FILE_NAMES_CONTAINING_PUBLICLY_KNOWN_HMAC_SECRETS.stream()
                .forEach(
                        (fileName) -> {
                            Set<String> values = JWTUtils.readFileContentsFromResources(fileName);
                            if (values != null && values.size() != 0) {
                                publiclyKnownHMacSecrets.addAll(values);
                            }
                        });
    }

    public static JWTConfiguration getInstance() {
        if (jwtConfiguration == null) {
            synchronized (JWTConfiguration.class) {
                if (jwtConfiguration == null) {
                    jwtConfiguration = new JWTConfiguration();
                }
            }
        }
        return jwtConfiguration;
    }

    public String getTrustStorePath() {
        return trustStorePath;
    }

    public void setTrustStorePath(String trustStorePath) {
        this.trustStorePath = trustStorePath;
        this.getConfig().setProperty(PARAM_TRUST_STORE_PATH, trustStorePath);
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
        this.getConfig().setProperty(PARAM_TRUST_STORE_PASSWORD, trustStorePassword);
    }

    public String getRsaPrivateKeyFileChooserPath() {
        return rsaPrivateKeyFileChooserPath;
    }

    public void setRsaPrivateKeyFileChooserPath(String rsaPrivateKeyFileChooserPath) {
        this.rsaPrivateKeyFileChooserPath = rsaPrivateKeyFileChooserPath;
    }

    public void setHMacSignatureKey(char[] hmacSignatureKey) {
        this.hmacSignatureKey = hmacSignatureKey;
    }

    public char[] getHMacSignatureKey() {
        return hmacSignatureKey;
    }

    public boolean isEnableClientConfigurationScan() {
        return enableClientConfigurationScan;
    }

    public void setEnableClientConfigurationScan(boolean enableClientSideConfiguration) {
        this.enableClientConfigurationScan = enableClientSideConfiguration;
        this.getConfig()
                .setProperty(PARAM_ENABLE_CLIENT_CONFIGURATION_SCAN, enableClientSideConfiguration);
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void parseImpl() {
        this.setTrustStorePath(getConfig().getString(PARAM_TRUST_STORE_PATH));
        this.setTrustStorePassword(getConfig().getString(PARAM_TRUST_STORE_PASSWORD));
        this.setEnableClientConfigurationScan(
                getBoolean(PARAM_ENABLE_CLIENT_CONFIGURATION_SCAN, false));
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    /**
     * There are publicly available well known JWT HMac Secrets. This API provides all those secrets
     * and help in finding JWT's signed using these weak secrets.
     *
     * @return publicly known HMac Secrets
     */
    public Set<String> getPubliclyKnownHMacSecrets() {
        return publiclyKnownHMacSecrets;
    }
}
