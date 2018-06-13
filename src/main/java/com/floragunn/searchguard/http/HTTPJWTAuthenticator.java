/*
 * Copyright 2015-2017 floragunn GmbH
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
 * 
 */

package com.floragunn.searchguard.http;

import static java.util.Collections.emptyList;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWSVerifier;
import org.apache.knox.gateway.services.security.token.impl.JWT;
import org.apache.knox.gateway.services.security.token.impl.JWTToken;
import org.apache.knox.gateway.util.CertificateUtils;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class HTTPJWTAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Settings settings;
    private final String CONFIG_EXPECTED_AUDIENCES = "expected_audiences";
    private final String CONFIG_VERIFICATION_PEM = "signing_key";
    private final String COOKIE_HEADER_NAME = "Cookie";
    private final String CONFIG_COOKIE_NAME = "cookie_name";
    private final String DEFAULT_COOKIE_NAME = "hadoop-jwt";

    public HTTPJWTAuthenticator(Settings settings, final Path configPath) {
        super();
        this.settings = settings;
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext context) {
        log.debug("headers {}", request.getHeaders());
        
        final String authorizationHeader = request.header("Authorization");
        String wireToken = null;
        String username = null;
        if (!Strings.isNullOrEmpty(authorizationHeader) && (authorizationHeader.trim().toLowerCase().startsWith("bearer "))) {
            wireToken = authorizationHeader.substring(7);
        } else {
            wireToken = getJWTTokenFromCookie(request);
        }
        if (Strings.isNullOrEmpty(wireToken)) {
            log.debug("No valid 'Bearer Authorization' or 'Cookie' found in header, send 401");
            return null;
        } else {
            log.debug("token found: " + wireToken);
               try {
                    JWTToken token = new JWTToken(wireToken);
                    boolean verified = false;
                    verified = verifyToken(token);
                    if (verified) {
                        Date expires = token.getExpiresDate();
                        log.debug("token expiry date: " + expires.toString());
                        if (expires == null || new Date().before(expires)) {
                            boolean audValid = validateAudiences(token);
                            if (audValid) {
                                username = token.getSubject();
                            } else {
                                log.debug("Failed to validate audience, send 401");
                            }
                        } else {
                            log.debug("Token expired, send 401");
                        }
                    } else {
                        log.debug("Unable to verify token, send 401");
                    }
                } catch (ParseException ex) {
                    if (log.isDebugEnabled()) {
                        ex.printStackTrace();
                    }
                    log.error("Exception in verifying JWT token : ", ex.toString());
                }
            
            if (Strings.isNullOrEmpty(username)) {
                log.debug("Appropriate user not found, send 401");
                return null;
            }
            String password = " ";
            log.debug("JWT authentication successfull, user : " + username);
            return new AuthCredentials(username, password.getBytes(StandardCharsets.UTF_8)).markComplete();
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "jwt";
    }
    
    private boolean verifyToken(JWT token) {       
        boolean rc = false;
        String verificationPem = settings.get(CONFIG_VERIFICATION_PEM);
        try {
            RSAPublicKey publicKey = CertificateUtils.parseRSAPublicKey(verificationPem);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            rc = token.verify(verifier);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                e.printStackTrace();
            }
            log.warn("Exception in verifying signature : ", e.toString());
            return false;
        }
        return rc;
    }
    
    private boolean validateAudiences(JWTToken jwtToken) {
        boolean valid = false;
        String expectedAudiences = settings.get(CONFIG_EXPECTED_AUDIENCES);
        ArrayList<String> audiences = null;
        if (!Strings.isNullOrEmpty(expectedAudiences)) {
            String[] audArray = expectedAudiences.split(",");
            audiences = new ArrayList<String>();
            for (String a : audArray) {
                audiences.add(a);
            }
        }
        String[] tokenAudienceList = jwtToken.getAudienceClaims();
        if (audiences == null) {
            valid = true;
        } else {
            for (String aud : tokenAudienceList) {
                if (audiences.contains(aud)) {
                    valid = true;
                    break;
                }
            }
        }
        return valid;
    }

    private String getJWTTokenFromCookie(final RestRequest request) {
        String cookieName = settings.get(CONFIG_COOKIE_NAME, DEFAULT_COOKIE_NAME);
        String cookieHeader = COOKIE_HEADER_NAME;
        String cookieToken = null;
        String rawCookie = request.header(cookieHeader);
        if (rawCookie == null) {
                //Try with lower case
            rawCookie = request.header(cookieHeader.toLowerCase());
            if (rawCookie == null) return null;
        }
        
        String[] rawCookieParams = rawCookie.split(";");
        for(String rawCookieNameAndValue :rawCookieParams) {
            String[] rawCookieNameAndValuePair = rawCookieNameAndValue.split("=");
            if ((rawCookieNameAndValuePair.length > 1) &&
                        (rawCookieNameAndValuePair[0].trim().equalsIgnoreCase(cookieName))) {
                cookieToken = rawCookieNameAndValuePair[1];
                break;
            }
        }
        return cookieToken;
    }
}
