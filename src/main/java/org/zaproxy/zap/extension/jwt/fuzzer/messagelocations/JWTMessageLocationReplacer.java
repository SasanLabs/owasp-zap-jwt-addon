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
package org.zaproxy.zap.extension.jwt.fuzzer.messagelocations;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.SortedSet;
import org.apache.commons.io.FileUtils;
import org.json.JSONObject;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacer;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTConstants;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.model.MessageLocation;

/**
 * {@code JWTMessageLocationReplacer} is used to replace the {@link JWTMessageLocation} present in
 * {@link HttpMessage} with the fuzzed value/replacement.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTMessageLocationReplacer implements MessageLocationReplacer<HttpMessage> {

    private HttpMessage message;

    @Override
    public boolean supports(MessageLocation location) {
        return supports(location.getClass());
    }

    @Override
    public boolean supports(Class<? extends MessageLocation> classLocation) {
        return JWTMessageLocation.class.isAssignableFrom(classLocation);
    }

    @Override
    public void init(HttpMessage message) {
        this.message = message.cloneAll();
    }

    @Override
    public HttpMessage replace(SortedSet<? extends MessageLocationReplacement<?>> replacements)
            throws InvalidMessageException {
        if (message == null) {
            throw new IllegalStateException("Replacer not initialised.");
        }

        Replacer requestHeaderReplacement = null;
        Replacer requestBodyReplacement = null;
        Replacer responseHeaderReplacement = null;
        Replacer responseBodyReplacement = null;

        Replacer currentReplacement = null;
        for (MessageLocationReplacement<?> replacement : replacements) {
            MessageLocation location = replacement.getMessageLocation();
            if (!(location instanceof JWTMessageLocation)) {
                continue;
            }

            JWTMessageLocation jwtMessageLocation = (JWTMessageLocation) location;
            switch (jwtMessageLocation.getLocation()) {
                case REQUEST_HEADER:
                    if (requestHeaderReplacement == null) {
                        requestHeaderReplacement =
                                new Replacer(
                                        message.getRequestHeader().toString(), jwtMessageLocation);
                    }
                    currentReplacement = requestHeaderReplacement;
                    break;
                case REQUEST_BODY:
                    if (requestBodyReplacement == null) {
                        requestBodyReplacement =
                                new Replacer(
                                        message.getRequestBody().toString(), jwtMessageLocation);
                    }
                    currentReplacement = requestBodyReplacement;
                    break;
                case RESPONSE_HEADER:
                    if (responseHeaderReplacement == null) {
                        responseHeaderReplacement =
                                new Replacer(
                                        message.getResponseHeader().toString(), jwtMessageLocation);
                    }
                    currentReplacement = responseHeaderReplacement;
                    break;
                case RESPONSE_BODY:
                    if (responseBodyReplacement == null) {
                        responseBodyReplacement =
                                new Replacer(
                                        message.getResponseBody().toString(), jwtMessageLocation);
                    }
                    currentReplacement = responseBodyReplacement;
                    break;
                default:
                    currentReplacement = null;
            }

            if (currentReplacement != null) {
                try {
                    currentReplacement.replace(
                            jwtMessageLocation, replacement.getReplacement().toString());
                } catch (JWTException e) {
                    throw new InvalidMessageException(e);
                }
            }
        }

        HttpMessage replacedMessage = message.cloneAll();
        if (requestHeaderReplacement != null) {
            try {
                replacedMessage.setRequestHeader(requestHeaderReplacement.getReplacedValue());
            } catch (HttpMalformedHeaderException | JWTException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (requestBodyReplacement != null) {
            try {
                replacedMessage.setRequestBody(requestBodyReplacement.getReplacedValue());
            } catch (JWTException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (responseHeaderReplacement != null) {
            try {
                replacedMessage.setResponseHeader(responseHeaderReplacement.getReplacedValue());
            } catch (HttpMalformedHeaderException | JWTException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (responseBodyReplacement != null) {
            try {
                replacedMessage.setResponseBody(responseBodyReplacement.getReplacedValue());
            } catch (JWTException e) {
                throw new InvalidMessageException(e);
            }
        }

        return replacedMessage;
    }

    private static class Replacer {

        private StringBuilder value;
        private int offset;
        private JWTHolder jwtHolder;
        private FuzzerJWTSignatureOperation fuzzerJWTSignatureOperation;
        private JWTMessageLocation jwtMessageLocation;

        /**
         * This constructor accepts the {@code JWTMessageLocation} to use the common properties
         * which are same for all the {@code JWTMessageLocation}s like JWT Token and Signature
         * Operation.
         *
         * @param originalValue
         * @param jwtMessageLocation
         * @throws InvalidMessageException
         */
        private Replacer(String originalValue, JWTMessageLocation jwtMessageLocation)
                throws InvalidMessageException {
            value = new StringBuilder(originalValue);
            try {
                this.jwtHolder = JWTHolder.parseJWTToken(jwtMessageLocation.getValue());
                this.jwtMessageLocation = jwtMessageLocation;
                this.fuzzerJWTSignatureOperation =
                        jwtMessageLocation.getFuzzerJWTSignatureOperation();
            } catch (JWTException e) {
                throw new InvalidMessageException(e);
            }
        }

        private RSAPrivateKey getRSAPrivateKey() throws JWTException {
            File pemFile =
                    new File(JWTConfiguration.getInstance().getRsaPrivateKeyFileChooserPath());
            try {
                String certAndKey = FileUtils.readFileToString(pemFile, StandardCharsets.US_ASCII);
                byte[] keyBytes = SslCertificateUtils.extractPrivateKey(certAndKey);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                return (RSAPrivateKey) factory.generatePrivate(spec);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new JWTException("Error occurred: ", e);
            }
        }

        public void replace(JWTMessageLocation jwtMessageLocation, String value)
                throws JWTException {
            boolean isHeaderField = jwtMessageLocation.isHeaderField();
            String key = jwtMessageLocation.getKey();
            JSONObject jsonObject;
            if (isHeaderField) {
                jsonObject = new JSONObject(this.jwtHolder.getHeader());
            } else {
                jsonObject = new JSONObject(this.jwtHolder.getPayload());
            }
            jsonObject.remove(key);
            jsonObject.put(key, value);
            if (isHeaderField) {
                jwtHolder.setHeader(jsonObject.toString());
            } else {
                jwtHolder.setPayload(jsonObject.toString());
            }
        }

        /**
         * @return value after replacing JWT present in originalValue with fuzzed token.
         * @throws JWTException is thrown if algorithm to sign the fuzzed token is invalid.
         */
        public String getReplacedValue() throws JWTException {
            String jwtToken = null;
            if (this.fuzzerJWTSignatureOperation.equals(FuzzerJWTSignatureOperation.NO_SIGNATURE)) {
                jwtHolder.setSignature(JWTUtils.getBytes(""));
                jwtToken = jwtHolder.getBase64EncodedToken();
            } else if (this.fuzzerJWTSignatureOperation.equals(
                    FuzzerJWTSignatureOperation.NEW_SIGNATURE)) {
                String algorithm = jwtHolder.getAlgorithm();
                if (algorithm.startsWith(JWTConstants.JWT_HMAC_ALGORITHM_IDENTIFIER)) {
                    jwtToken =
                            JWTUtils.getBase64EncodedHMACSignedToken(
                                    JWTUtils.getBytes(
                                            jwtHolder.getBase64EncodedTokenWithoutSignature()),
                                    JWTUtils.getBytes(
                                            JWTConfiguration.getInstance().getHMacSignatureKey()),
                                    algorithm);
                } else if (algorithm.startsWith(JWTConstants.JWT_RSA_ALGORITHM_IDENTIFIER)) {
                    jwtToken =
                            JWTUtils.getBase64EncodedRSSignedToken(jwtHolder, getRSAPrivateKey());
                } else {
                    throw new JWTException("Unsupported Algorithm type: " + algorithm);
                }
            }
            if (jwtToken != null) {
                this.value.replace(
                        offset + jwtMessageLocation.getStart(),
                        offset + jwtMessageLocation.getEnd(),
                        jwtToken.trim());
                offset +=
                        value.length()
                                - (jwtMessageLocation.getEnd() - jwtMessageLocation.getStart());
            }
            return this.value.toString();
        }
    }
}
