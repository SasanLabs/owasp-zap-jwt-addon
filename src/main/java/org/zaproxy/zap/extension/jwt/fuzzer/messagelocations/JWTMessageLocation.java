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

import java.io.Serializable;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.DefaultTextHttpMessageLocation;
import org.zaproxy.zap.model.MessageLocation;

/**
 * {@code JWTMessageLocation} represent the JWT location in {@link HttpMessage}. As JWT is a
 * combination of 3 components i.e. {@code Header}, {@code Payload} and {@code Signature}. All three
 * components are base64 Url encoded, where {@code Header} is {@code JSON object} and {@code
 * Payload} can be a JSON component but {@code Signature} is binary component.
 *
 * <p>So JWT value cannot be fuzzed/replaced with some other value directly, we need to fuzz the
 * {@code JSON object} which {@code Header} and {@code Payload} represents.
 *
 * <p>Hence this {@code JWTMessageLocation} contains {@code key} field which is {@code JSON object's
 * key} to be fuzzed and {@code isHeaderField} holds the information about where does the {@code
 * JSON object's key} resides i.e. in {@code Header} or {@code Payload}
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTMessageLocation extends DefaultTextHttpMessageLocation implements Serializable {

    private static final long serialVersionUID = 1L;

    /** JSON Object's Key field */
    private String key;

    /**
     * If {@code key} field is present in JWT {@code Header} Component or {@code Payload} Component.
     */
    private boolean isHeaderField;

    /** {@code Signature} Operation after fuzzing JWT */
    private FuzzerJWTSignatureOperation fuzzerJWTSignatureOperation;

    /**
     * @param location in {@code HttpMessage} i.e. Request's Header/Body or Response's Header/Body
     * @param start index of JWT in {@code HttpMessage}
     * @param end index of JWT in {@code HttpMessage}
     * @param value JWT value
     * @param key JSON Object's Key field
     * @param isHeaderOrPayload provided {@param key} is present in Header component or not.
     * @param fuzzerJWTSignatureOperation JWT signature operation
     */
    public JWTMessageLocation(
            Location location,
            int start,
            int end,
            String value,
            String key,
            boolean isHeaderOrPayload,
            FuzzerJWTSignatureOperation fuzzerJWTSignatureOperation) {
        super(location, start, end, value);
        this.key = key;
        this.isHeaderField = isHeaderOrPayload;
        this.fuzzerJWTSignatureOperation = fuzzerJWTSignatureOperation;
    }

    /** @return JSON Object's Key field */
    public String getKey() {
        return key;
    }

    /** @param key JSON Object's Key field */
    public void setKey(String key) {
        this.key = key;
    }

    /** @return true of Key field is present in Header */
    public boolean isHeaderField() {
        return isHeaderField;
    }

    /** @param isHeaderField */
    public void setHeaderField(boolean isHeaderField) {
        this.isHeaderField = isHeaderField;
    }

    /** @return FuzzerJWTSignatureOperation */
    public FuzzerJWTSignatureOperation getFuzzerJWTSignatureOperation() {
        return fuzzerJWTSignatureOperation;
    }

    /** @param fuzzerJWTSignatureOperation */
    public void setFuzzerJWTSignatureOperation(
            FuzzerJWTSignatureOperation fuzzerJWTSignatureOperation) {
        this.fuzzerJWTSignatureOperation = fuzzerJWTSignatureOperation;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + (isHeaderField ? 1231 : 1237);
        result = prime * result + ((key == null) ? 0 : key.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!super.equals(obj)) return false;
        if (getClass() != obj.getClass()) return false;
        JWTMessageLocation other = (JWTMessageLocation) obj;
        if (isHeaderField != other.isHeaderField) return false;
        if (key == null) {
            if (other.key != null) return false;
        } else if (!key.equals(other.key)) return false;
        return true;
    }

    @Override
    public int compareTo(MessageLocation otherLocation) {
        if (!(otherLocation instanceof JWTMessageLocation)) {
            return 1;
        }
        JWTMessageLocation that = (JWTMessageLocation) otherLocation;

        int result = Boolean.compare(that.isHeaderField, this.isHeaderField);
        if (result != 0) {
            return result;
        }

        result = this.key.compareTo(that.key);
        if (result != 0) {
            return result;
        }

        if (result != 0) {
            return result;
        }
        return super.compareTo(otherLocation);
    }

    @Override
    public boolean overlaps(MessageLocation otherLocation) {
        return this.equals(otherLocation);
    }
}
