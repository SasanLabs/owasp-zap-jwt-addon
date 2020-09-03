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

import org.zaproxy.zap.extension.jwt.JWTI18n;

/**
 * This class represents the operation on JWT Signature after fuzzing the {@code Headers} and {@code
 * Payload} fields. <br>
 * Following are the operations on the Signatures:
 *
 * <ol>
 *   <li>Either no signature component will be added to JWT e.g. in case of {@code None} hashing
 *       algorithm we don't require the signature component.
 *   <li>Generating new signature for the fuzzed token. This is useful for finding vulnerabilities
 *       in JWT fields where say a field value cause {@code SQLInjection} kind of vulnerabilities.
 *   <li>Using the same old signature for the fuzzed JWT too.
 * </ol>
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public enum FuzzerJWTSignatureOperation {

    /** No {@code Signature} component. */
    NO_SIGNATURE("jwt.fuzzer.signature.operation.nosignature"),

    /** New {@code Signature} component needs to be generated and appended with fuzzed token. */
    NEW_SIGNATURE("jwt.fuzzer.signature.operation.newsignature"),

    /** Same {@code Signature} component appended to fuzzed token. */
    SAME_SIGNATURE("jwt.fuzzer.signature.operation.samesignature");

    private String labelKey;

    private FuzzerJWTSignatureOperation(String labelKey) {
        this.labelKey = labelKey;
    }

    public String toString() {
        return JWTI18n.getResourceBundle().getString(labelKey);
    }
}
