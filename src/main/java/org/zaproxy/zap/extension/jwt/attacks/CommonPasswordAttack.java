package org.zaproxy.zap.extension.jwt.attacks;

import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTConstants;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * There are publicly available well known JWT HMac Secrets and This attack checks if JWT is signed
 * using weak well known secret.
 *
 * <p>Special thanks to <a
 * href="https://lab.wallarm.com/340-weak-jwt-secrets-you-should-check-in-your-code/">Wallarm.com</a>
 * for collating the list of such weak secrets and making them as opensource.
 *
 * <p>For knowing all the secrets please visit: <a
 * href="https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list">Weak
 * Publicly known HMac Secrets</a>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class CommonPasswordAttack implements JWTAttack {

    private static final Logger LOGGER = Logger.getLogger(CommonPasswordAttack.class);

    @Override
    public boolean executeAttack(ServerSideAttack serverSideAttack) {
        List<String> secrets = new ArrayList<String>();
        JWTConfiguration.getInstance()
                .getUrlVsHMacSecrets()
                .forEach(
                        (key, values) -> {
                            secrets.addAll(values);
                        });
        // Checks if HMac is the actual algorithm for the JWT
        if (JWTConstants.JWT_HMAC_ALGO_TO_JAVA_ALGORITHM_MAPPING.containsKey(
                serverSideAttack.getJwtHolder().getAlgorithm())) {
            for (String secret : secrets) {
                if (serverSideAttack.getJwtActiveScanner().isStop()) {
                    return false;
                }
                serverSideAttack.getJwtActiveScanner().decreaseRequestCount();
                JWTHolder jwtHolder = serverSideAttack.getJwtHolder();
                try {
                    String tokenSignedWithWeakSecret =
                            JWTUtils.getBase64EncodedHMACSignedToken(
                                    JWTUtils.getBytes(
                                            jwtHolder.getBase64EncodedTokenWithoutSignature()),
                                    JWTUtils.getBytes(
                                            JWTConfiguration.getInstance().getHMacSignatureKey()),
                                    jwtHolder.getAlgorithm());
                    if (tokenSignedWithWeakSecret.equals(jwtHolder.getBase64EncodedToken())) {
                        this.raiseAlert(
                                "",
                                VulnerabilityType.ALGORITHM_CONFUSION,
                                Alert.RISK_HIGH,
                                Alert.CONFIDENCE_HIGH,
                                jwtHolder.getBase64EncodedToken(),
                                serverSideAttack);
                        return true;
                    }
                } catch (JWTException e) {
                    LOGGER.error("An error occurred while getting signed manipulated tokens", e);
                }
            }
        }
        return false;
    }
}
