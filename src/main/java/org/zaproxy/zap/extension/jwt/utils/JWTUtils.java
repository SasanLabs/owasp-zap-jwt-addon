/**
 * Copyright 2020 SasanLabs
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
package org.zaproxy.zap.extension.jwt.utils;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.BASE64_PADDING_CHARACTER_REGEX;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.BEARER_TOKEN_KEY;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.BEARER_TOKEN_REGEX;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_PSS_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_PERIOD_CHARACTER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_REGEX_PATTERN;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.exception.JWTException;

/**
 * Contains Utility methods for handling various operations on JWT Tokens.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTUtils {

    private static final Logger LOGGER = Logger.getLogger(JWTUtils.class);

    /**
     * Converts string to bytes. This method assumes that token is in UTF-8 charset which is as per
     * the JWT specifications.
     *
     * @param token
     * @return resultant byte array
     */
    public static byte[] getBytes(String token) {
        return token.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Converts char array to byte array securely. Not using string to byte array manipulation
     * because of security concerns. This method assumes that token is in UTF-8 charset which is as
     * per the JWT specifications.
     *
     * @param token
     * @return resultant byte array
     */
    public static byte[] getBytes(char[] token) {
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(token));
        byte[] byteArray = new byte[byteBuffer.remaining()];
        // Populate the provided array
        byteBuffer.get(byteArray);
        return byteArray;
    }

    /**
     * Converts bytes to String. This method assumes that bytes provides are as per UTF-8 charset.
     *
     * @param tokenBytes
     * @return {@code String} by decoding in UTF_8 charset.
     */
    public static String getString(byte[] tokenBytes) {
        return new String(tokenBytes, StandardCharsets.UTF_8);
    }

    /**
     * Using <a href="https://en.wikipedia.org/wiki/Base64#URL_applications">Base64 URL Safe
     * encoding</a>. because of JWT specifications.<br>
     * Also we are removing the padding as per <a
     * href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515</a> padding is not there in JWT.
     *
     * @param token
     * @return base64 url encoded provided token.
     */
    public static String getBase64UrlSafeWithoutPaddingEncodedString(String token) {
        return JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(getBytes(token));
    }

    /**
     * Using <a href="https://en.wikipedia.org/wiki/Base64#URL_applications">Base64 URL Safe
     * encoding</a>. because of JWT specifications.<br>
     * Also we are removing the padding as per <a
     * href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515</a> padding is not there in JWT.
     *
     * @param token
     * @return base64 url encoded provided token.
     */
    public static String getBase64UrlSafeWithoutPaddingEncodedString(byte[] token) {
        return JWTUtils.getString(Base64.getUrlEncoder().encode(token))
                .replaceAll(BASE64_PADDING_CHARACTER_REGEX, "");
    }

    /**
     * Checks if the provided value is in a valid JWT format.
     *
     * @param jwtToken
     * @return {@code true} if the provided value is in a valid JWT format else {@code false}
     */
    public static boolean isTokenValid(String jwtToken) {
        if (Objects.isNull(jwtToken)) {
            return false;
        }
        return JWT_TOKEN_REGEX_PATTERN.matcher(jwtToken).matches();
    }

    /**
     * Signs token using provided secretKey based on the provided algorithm. This method only
     * handles signing of token using HS*(Hmac + Sha*) based algorithm.<br>
     *
     * <p>Note: This method adds custom java based implementation of HS* algorithm and doesn't use
     * any library like Nimbus+JOSE or JJWT and reason for this is, libraries are having validations
     * related to Key sizes and they don't allow weak keys so for signing token using weak keys (for
     * finding vulnerabilities in web applications that are using old implementations or custom
     * implementations) is not possible therefore added this custom implementation for HS*
     * algorithms.
     *
     * <p>
     *
     * @param token to be signed.
     * @param secretKey used for signing the Hmac token.
     * @param algorithm Hmac signature algorithm e.g. HS256, HS384, HS512
     * @return Final Signed JWT Base64 encoded Hmac signed token.
     * @throws JWTException if provided Hmac algorithm is not supported.
     */
    public static String getBase64EncodedHMACSignedToken(
            byte[] token, byte[] secretKey, String algorithm) throws JWTException {
        try {
            if (JWTConstants.JWT_HMAC_ALGO_TO_JAVA_ALGORITHM_MAPPING.containsKey(algorithm)) {
                Mac hmacSHA =
                        Mac.getInstance(
                                JWTConstants.JWT_HMAC_ALGO_TO_JAVA_ALGORITHM_MAPPING.get(
                                        algorithm));
                SecretKeySpec hmacSecretKey = new SecretKeySpec(secretKey, hmacSHA.getAlgorithm());
                hmacSHA.init(hmacSecretKey);
                byte[] tokenSignature = hmacSHA.doFinal(token);
                String base64EncodedSignature =
                        JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(tokenSignature);
                return JWTUtils.getString(token)
                        + JWT_TOKEN_PERIOD_CHARACTER
                        + base64EncodedSignature;
            } else {
                throw new JWTException(algorithm + " is not a supported HMAC algorithm.");
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new JWTException(
                    "Exception occurred while Signing token: " + getString(token), e);
        }
    }

    /**
     * Signs token using provided {@param privateKey} using RSA Signature algorithm. This method
     * only handles signing of token using RS*(RSA + Sha*) based algorithm.<br>
     *
     * @param jwtHolder Token holder which needs contains the fuzzed values
     * @param privateKey RSA private Key
     * @return Final Signed JWT using provided {@param privateKey}.
     * @throws JWTException
     */
    public static String getBase64EncodedRSSignedToken(JWTHolder jwtHolder, PrivateKey privateKey)
            throws JWTException {
        if (jwtHolder.getAlgorithm().startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)
                || jwtHolder.getAlgorithm().startsWith(JWT_RSA_PSS_ALGORITHM_IDENTIFIER)) {
            String base64EncodedNewHeaderAndPayload =
                    jwtHolder.getBase64EncodedTokenWithoutSignature();
            if (privateKey != null) {
                RSASSASigner rsassaSigner = new RSASSASigner(privateKey);
                try {
                    return base64EncodedNewHeaderAndPayload
                            + JWTConstants.JWT_TOKEN_PERIOD_CHARACTER
                            + rsassaSigner.sign(
                                    JWSHeader.parse(
                                            Base64URL.from(
                                                    JWTUtils
                                                            .getBase64UrlSafeWithoutPaddingEncodedString(
                                                                    jwtHolder.getHeader()))),
                                    JWTUtils.getBytes(
                                            jwtHolder.getBase64EncodedTokenWithoutSignature()));
                } catch (JOSEException | ParseException e) {
                    throw new JWTException("Error occurred: ", e);
                }
            }
        }
        return null;
    }

    /**
     * Utility method for reading the PEM file and building RSAPrivateKey from it.
     *
     * @param pemFilePath PEM File Path which contains the RSA Private Key
     * @return RSAPrivateKey by reading PEM file containing the RSA Private Key.
     * @throws JWTException if unable to read the provided file path or key specification is
     *     incorrect etc.
     */
    public static RSAPrivateKey getRSAPrivateKeyFromProvidedPEMFilePath(String pemFilePath)
            throws JWTException {
        File pemFile = new File(pemFilePath);
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

    private static boolean hasBearerToken(String value) {
        return Pattern.compile(BEARER_TOKEN_REGEX).matcher(value).find();
    }

    /**
     * This utility method removes {@literal BEARER_TOKEN_REGEX} from the value. For now it is just
     * removing {@literal BEARER_TOKEN_REGEX} but in future we might need to remove other type of
     * schemes too.
     *
     * @param value the value of the parameter under testing
     * @return value by replacing the {@literal BEARER_TOKEN_REGEX}
     */
    public static String extractingJWTFromParamValue(String value) {
        if (hasBearerToken(value)) {
            value = value.replaceAll(BEARER_TOKEN_REGEX, "").trim();
        }
        return value;
    }

    /**
     * This utility method adds the {@literal BEARER_TOKEN_KEY} to the value. This method reverses
     * the operation performed by {@link JWTUtils#extractingJWTFromParamValue}
     *
     * @param value the value of the parameter under testing
     * @param jwtToken value of the manipulated token
     * @return jwt token by adding {@literal BEARER_TOKEN_REGEX}
     */
    public static String addingJWTToParamValue(String value, String jwtToken) {
        if (hasBearerToken(value)) {
            jwtToken = BEARER_TOKEN_KEY + " " + jwtToken;
        }
        return jwtToken;
    }

    /**
     * This utility method is used to check the provided String is a valid JSON or not.
     *
     * @param value JSON String
     * @return true if provided value is a valid JSON else false.
     */
    public static boolean isValidJson(String value) {
        try {
            new JSONObject(value);
        } catch (JSONException ex) {
            return false;
        }
        return true;
    }

    /**
     * Generic utility to read contents from the file and returning the provided content as list of
     * Strings.
     *
     * @param fileName
     * @return content from file as list of strings
     */
    public static Set<String> readFileContentsFromResources(String fileName) {
        Set<String> values = new HashSet<>();
        try (BufferedReader bufferedReader =
                new BufferedReader(
                        new InputStreamReader(JWTUtils.class.getResourceAsStream(fileName)))) {
            String inputLine;
            while ((inputLine = bufferedReader.readLine()) != null) {
                if (StringUtils.isNotBlank(inputLine)) {
                    values.add(inputLine);
                }
            }
        } catch (Exception ex) {
            LOGGER.warn("Unable to read publicly known secrets from: " + fileName, ex);
        }
        return values;
    }
}
