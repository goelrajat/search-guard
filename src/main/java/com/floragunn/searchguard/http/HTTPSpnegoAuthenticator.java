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

import java.io.File;
import java.io.FilePermission;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.security.auth.AuthPermission;
import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.ietf.jgss.GSSException;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;


import org.apache.kerby.kerberos.kerb.KrbException;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.server.marshall.spnego.SpnegoInitToken;
import com.kerb4j.server.marshall.spnego.SpnegoKerberosMechToken;
import com.kerb4j.server.marshall.Kerb4JException;
import com.kerb4j.server.marshall.pac.Pac;
import com.kerb4j.server.marshall.pac.PacLogonInfo;
import com.kerb4j.server.marshall.pac.PacSid;
import com.kerb4j.common.util.base64.Base64Codec;

public class HTTPSpnegoAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    public final static String SERVER_KEYTAB_PATH = "/etc/security/keytabs/es.service.keytab";
    public final static String KRB5_CONF = "/etc/krb5.conf";
    private static SpnegoClient spnegoClient = null;
    private Settings settings = null;

    public HTTPSpnegoAuthenticator(Settings settings, final Path configPath) {
        super();
        this.settings = settings;
        Boolean krbDebug = settings.getAsBoolean("krb_debug", false);
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                System.setProperty("sun.security.krb5.debug", krbDebug.toString());
                return null;
            }
        });
        
        if (spnegoClient == null) {
            // This block can be removed as we are doing initialization from PrivilegesEvaluator
            String svcName = settings.get("acceptor_principal");        
            String keytabPath = settings.get("acceptor_keytab_filepath", SERVER_KEYTAB_PATH);
            String krbConf = settings.get("krb5_filepath", KRB5_CONF);
        
            initSpnegoClient(svcName, keytabPath, krbConf);
        }
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext context) {
        log.debug("headers {}", request.getHeaders());
        
        String negotiateHeaderValue = null;
        if (!Strings.isNullOrEmpty(request.header("Authorization")))
            negotiateHeaderValue= request.header("Authorization").substring(10);
        if (Strings.isNullOrEmpty(negotiateHeaderValue) || !(request.header("Authorization").trim().toLowerCase().startsWith("negotiate "))) {
            log.warn("Either there is no auth token or negotiate header not present. Skipping Spnego auth");
            return null;           
        }
        
        byte[] decoded = Base64Codec.decode(negotiateHeaderValue);
        
        AuthCredentials retObj = AccessController.doPrivileged(new PrivilegedAction<AuthCredentials>() {
            public AuthCredentials run() {
                SpnegoContext ctx = null;
                PacLogonInfo logonInfo = null;
                String usrName = null;
                
                try {
                    ctx =  spnegoClient.createAcceptContext();
                    byte[] retVal = ctx.acceptToken(decoded);
                    if (retVal == null) {
                        log.error("Spnego authentication failed");
                        return null;
                    }
                    
                    Boolean stripFlag = settings.getAsBoolean("strip_realm_from_principal", true);
                    usrName = stripRealmName(ctx.getSrcName().toString(), stripFlag);
                    log.debug("Spnego authentication successfull, user : " + usrName);
                    
                    try {
                        SpnegoInitToken spnegoInitToken = new SpnegoInitToken(decoded);
                        SpnegoKerberosMechToken spnegoKerberosMechToken = spnegoInitToken.getSpnegoKerberosMechToken();
                        Pac pac = spnegoKerberosMechToken.getPac(spnegoClient.getKerberosKeys());

                        if (pac != null) {
                            logonInfo = pac.getLogonInfo();
                            log.debug("Got valid pac and loginfo object");
                        }
                    } catch (Kerb4JException kje) {
                        if (log.isDebugEnabled()) {
                            kje.printStackTrace();
                        }
                        log.warn("Exception while retrieving user roles: " + kje.toString());
                    } catch (KrbException ke) {
                        if (log.isDebugEnabled()) {
                            ke.printStackTrace();
                        }
                        log.warn("Exception while retrieving user roles: " + ke.toString());
                    }
                    
                } catch (PrivilegedActionException e) {
                    if (log.isDebugEnabled()) {
                        e.printStackTrace();
                    }
                    log.warn("Exception while creating Spnego context: " + e.toString());
                    return null;
                } catch (GSSException ge) {
                    log.error("Error while validating token: " + ge.toString());
                    if (log.isDebugEnabled()) {
                        ge.printStackTrace();
                    }
                    return null;
                }
                finally {
                    try {
                        ctx.close();
                    } catch (Exception ie) {}
                }
                
                List<String> roles = null;
                if (logonInfo != null) {
                    roles = Stream.of(logonInfo.getGroupSids()).map(PacSid::toHumanReadableString).collect(Collectors.toList());
                    if (roles != null) {
                        log.debug("Retrieved roles: " + Arrays.toString(roles.toArray(new String[0])));
                        return new AuthCredentials(usrName, roles).markComplete();
                    }
                }
                
                String password = " ";
                return new AuthCredentials(usrName, password.getBytes(StandardCharsets.UTF_8)).markComplete();      
            }
        });
        
        if (retObj == null) {
            log.debug("Got null return val.");
        }
        return retObj;
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        final BytesRestResponse res;
        XContentBuilder response = getNegotiateResponseBody();
        
        if (response != null) {
            res = new BytesRestResponse(RestStatus.UNAUTHORIZED, response);         
        } else {
            res = new BytesRestResponse(RestStatus.UNAUTHORIZED, "");
        }
        
        if(creds == null || creds.getNativeCredentials() == null) {
            res.addHeader("WWW-Authenticate", "Negotiate");
        } else {
            res.addHeader("WWW-Authenticate", "Negotiate "+DatatypeConverter.printBase64Binary((byte[]) creds.getNativeCredentials()));
        }
        channel.sendResponse(res);
        return true;
    }

    private XContentBuilder getNegotiateResponseBody() {
        try {
            XContentBuilder nBody = XContentFactory.jsonBuilder();
            nBody.startObject();
            nBody.field("error");
            nBody.startObject();
            nBody.field("header");
            nBody.startObject();
            nBody.field("WWW-Authenticate", "Negotiate");
            nBody.endObject();
            nBody.endObject();
            nBody.endObject();
            return nBody;
        } catch (Exception ex) {
            log.error("Can't construct response body", ex);
            return null;
        }
    }
    
    @Override
    public String getType() {
        // TODO Auto-generated method stub
        return "kerberos";
    }
    
    private String stripRealmName(String name, boolean strip){
        if (strip && name != null) {
            final int i = name.indexOf('@');
            if (i > 0) {
                // Zero so we don;t leave a zero length name
                name = name.substring(0, i);
            }
        }
        
        return name;
    }
    
    public static SpnegoClient getSpnegoClient() {
        return spnegoClient;
    }
    
    public static void initSpnegoClient(String svcName, String keytabPath, String krbConf) {
        if (spnegoClient != null) {
            return;
        }
        
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                System.setProperty("java.security.krb5.conf", krbConf);
                return null;
            }
        });
        
        spnegoClient = SpnegoClient.loginWithKeyTab(svcName, keytabPath);
    }
}
