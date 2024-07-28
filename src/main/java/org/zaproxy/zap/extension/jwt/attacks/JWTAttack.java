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
package org.zaproxy.zap.extension.jwt.attacks;

import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * JWTAttack is the common interface for various JWT attacks.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public interface JWTAttack {

    /**
     * Verifies the attack and returns {@code true} if successful otherwise {@code false}.
     *
     * @param newJWTToken is the manipulated JWT token with various attacks.
     * @param serverSideAttack
     * @return {@code true} if attacks is successful else {@code false}
     */
    default boolean verifyJWTToken(String newJWTToken, ServerSideAttack serverSideAttack) {
        serverSideAttack.getJwtActiveScanRule().decreaseRequestCount();
        return serverSideAttack
                .getJwtActiveScanRule()
                .sendManipulatedMsgAndCheckIfAttackSuccessful(
                        serverSideAttack.getMsg(),
                        serverSideAttack.getParam(),
                        newJWTToken,
                        serverSideAttack.getParamValue());
    }

    /**
     * Raises Alert for JWT attack.
     *
     * @param messagePrefix prefix of the message key
     * @param vulnerabilityType type of the vulnerability. This will be appended to prefix for
     *     finding exact message key.
     * @param alertLevel represents the risk of the attack
     * @param confidenceLevel represents the confidence in the attack
     * @param serverSideAttack instance of {@link ServerSideAttack}
     */
    default void raiseAlert(
            String messagePrefix,
            VulnerabilityType vulnerabilityType,
            int alertLevel,
            int confidenceLevel,
            String jwtToken,
            ServerSideAttack serverSideAttack) {
        serverSideAttack
                .getJwtActiveScanRule()
                .raiseAlert(
                        alertLevel,
                        confidenceLevel,
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".name"),
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".desc"),
                        serverSideAttack.getMsg().getRequestHeader().getURI().toString(),
                        serverSideAttack.getParam(),
                        jwtToken,
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".refs"),
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".soln"),
                        serverSideAttack.getMsg());
    }

    /**
     * Manipulates the JWT token, executes an attack, and also raise alert if successful.
     *
     * @param serverSideAttack instance of {@link ServerSideAttack}
     * @return {@code true} if attack is successful else {@code false}
     */
    boolean executeAttack(ServerSideAttack serverSideAttack);
}
