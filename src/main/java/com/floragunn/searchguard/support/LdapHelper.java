package com.floragunn.searchguard.support;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import joptsimple.internal.Strings;

public class LdapHelper {
    public static Set<String> findUserGroup(Settings settings, String key) {
        String ldapServer = settings.getAsList(ConfigConstants.SEARCHGUARD_AUTH_LDAP_HOSTS).get(0);
        if (Strings.isNullOrEmpty(ldapServer)) {
            return null;
        }

        String bindUserDn = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_BIND_DN);
        String passwd = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_PASSWD);
 
        String userBase = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_USER_BASE);
        String userSearchFilter = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_USER_SEARCH);
        String userGroupAttribute = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_USER_GROUP_ATTR);
        
        String groupBase = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_GROUP_BASE);
        String groupSearchFilter = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_GROUP_SEARCH);
        String groupNameAttribute = settings.get(ConfigConstants.SEARCHGUARD_AUTH_LDAP_GROUP_NAME_ATTR);
        
        String userToBeSearched = key;  

        String userSearchDn = userBase.replaceAll("\\{0\\}", userToBeSearched);
        String userSearchFilterDn = userSearchFilter.replaceAll("\\{0\\}", userToBeSearched);
        
        Properties props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapServer);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, bindUserDn);
        props.put(Context.SECURITY_CREDENTIALS, passwd);
        
        DirContext ctx = null;
        NamingEnumeration<SearchResult> results = null;
        Set<String> res = new HashSet<String>();
        
        try {
            
            //ctx = new InitialDirContext(props);
            ctx = new InitialDirContext(props);
            String grpId = null;
            boolean gidFlag = false;

            if (!Strings.isNullOrEmpty(userGroupAttribute)) {
                SearchControls controls = new SearchControls();
                String[] attrIDs = { userGroupAttribute };
                controls.setReturningAttributes(attrIDs);
                controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
                results = ctx.search(userSearchDn, userSearchFilterDn, controls);
                Attribute gid = null;
                while (results.hasMore()) {
                    SearchResult searchResult = (SearchResult) results.next();
                    Attributes attributes = searchResult.getAttributes();
                    gid = attributes.get(userGroupAttribute);
                    break;
                }
                if (gid != null) {
                    if (userGroupAttribute.equalsIgnoreCase("gidNumber")) {
                        grpId = gid.get().toString();
                        gidFlag = true;
                    } else {
                        String pattern = "(.*)cn=((\\w|\\s)+),(.*)";
                        Pattern p = Pattern.compile(pattern);
                        for (int i = 0; i < gid.size(); i++) {
                            String grpDnName = gid.get(i).toString();
                            Matcher matcher = p.matcher(grpDnName);
                            if (matcher.matches()) {
                                String grpName = matcher.group(2);
                                res.add(grpName);
                            } else {
                                res.add(grpDnName);
                            }
                                
                        }
                    }
                }
            }
            if (!Strings.isNullOrEmpty(groupBase)) {
                String grpSearchDn1 = groupBase.replaceAll("\\{0\\}", userToBeSearched);
                String grpSearchFilterDn1 = groupSearchFilter.replaceAll("\\{0\\}", userToBeSearched);
                String grpSearchDn = grpSearchDn1;
                String grpSearchFilterDn = grpSearchFilterDn1;
                if (gidFlag) {
                    grpSearchDn = grpSearchDn1.replaceAll("\\{1\\}", grpId);
                    grpSearchFilterDn = grpSearchFilterDn1.replaceAll("\\{1\\}", grpId);
                }
                SearchControls grpCtrls = new SearchControls();
                String[] attrID1 = { userGroupAttribute, groupNameAttribute };
                grpCtrls.setReturningAttributes(attrID1);
                grpCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                
                results = ctx.search(grpSearchDn, grpSearchFilterDn, grpCtrls);
                while (results.hasMore()) {
                    SearchResult searchResult = (SearchResult) results.next();
                    Attributes attributes = searchResult.getAttributes();
                    Attribute grpName = attributes.get(groupNameAttribute);
                    if (grpName != null) {
                        res.add(grpName.get().toString());
                    }
                }
            } 
        } catch (Exception e) {
            System.out.println("Error in querying ldap : " + e.getMessage());
        }
        finally {
            try { 
                //results.close(); 
            ctx.close(); } catch(Exception ex) { }
        }
        
        return res;
        
    }

}
