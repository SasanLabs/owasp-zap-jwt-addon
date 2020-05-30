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
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
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
                                new Replacer(message.getRequestHeader().toString());
                    }
                    currentReplacement = requestHeaderReplacement;
                    break;
                case REQUEST_BODY:
                    if (requestBodyReplacement == null) {
                        requestBodyReplacement = new Replacer(message.getRequestBody().toString());
                    }
                    currentReplacement = requestBodyReplacement;
                    break;
                case RESPONSE_HEADER:
                    if (responseHeaderReplacement == null) {
                        responseHeaderReplacement =
                                new Replacer(message.getResponseHeader().toString());
                    }
                    currentReplacement = responseHeaderReplacement;
                    break;
                case RESPONSE_BODY:
                    if (responseBodyReplacement == null) {
                        responseBodyReplacement =
                                new Replacer(message.getResponseBody().toString());
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

                }
            }
        }

        HttpMessage replacedMessage = message.cloneAll();
        if (requestHeaderReplacement != null) {
            try {
                replacedMessage.setRequestHeader(requestHeaderReplacement.toString());
            } catch (HttpMalformedHeaderException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (requestBodyReplacement != null) {
            replacedMessage.setRequestBody(requestBodyReplacement.toString());
        }

        if (responseHeaderReplacement != null) {
            try {
                replacedMessage.setResponseHeader(responseHeaderReplacement.toString());
            } catch (HttpMalformedHeaderException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (responseBodyReplacement != null) {
            replacedMessage.setResponseBody(responseBodyReplacement.toString());
        }

        return replacedMessage;
    }

    private static class Replacer {

        private StringBuilder value;
        private int offset;

        private Replacer(String originalValue) {
            value = new StringBuilder(originalValue);
        }

        private RSAPrivateKey getPrivateKey() throws JWTException {
            File pemFile = new File("/");
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
            String jwtToken = jwtMessageLocation.getValue();
            JWTHolder jwtHolder = JWTHolder.parseJWTToken(jwtToken);
            JSONObject jsonObject;
            if (isHeaderField) {
                jsonObject = new JSONObject(jwtHolder.getHeader());
            } else {
                jsonObject = new JSONObject(jwtHolder.getPayload());
            }
            jsonObject.remove(key);
            jsonObject.put(key, value);
            if (isHeaderField) {
                jwtHolder.setHeader(jsonObject.toString());
            } else {
                jwtHolder.setPayload(jsonObject.toString());
            }
            if (jwtMessageLocation
                    .getFuzzerJWTSignatureOperation()
                    .equals(FuzzerJWTSignatureOperation.NO_SIGNATURE)) {
                jwtHolder.setSignature(JWTUtils.getBytes(""));
            } else if (jwtMessageLocation
                    .getFuzzerJWTSignatureOperation()
                    .equals(FuzzerJWTSignatureOperation.NEW_SIGNATURE)) {
                JWTUtils.getBase64EncodedRSSignedToken(jwtHolder, getPrivateKey());
            }
            jwtToken = jwtHolder.getBase64EncodedToken();
            this.value.replace(
                    offset + jwtMessageLocation.getStart(),
                    offset + jwtMessageLocation.getEnd() + 1,
                    jwtToken.trim());
            offset +=
                    value.length() - (jwtMessageLocation.getEnd() - jwtMessageLocation.getStart());
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }
}
