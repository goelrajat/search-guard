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

package com.floragunn.searchguard.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;

import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.OriginalIndices;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.elasticsearch.action.get.MultiGetAction;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchAction;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchScrollAction;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.termvectors.MultiTermVectorsAction;
import org.elasticsearch.action.termvectors.MultiTermVectorsRequest;
import org.elasticsearch.action.termvectors.TermVectorsRequest;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.reindex.ReindexAction;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.repositories.Repository;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.elasticsearch.snapshots.SnapshotId;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.snapshots.SnapshotUtils;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.RemoteClusterAware;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.SpecialPermission;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.http.HTTPSpnegoAuthenticator;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.UserGroupMappingCache;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.Sets;
import com.kerb4j.client.SpnegoClient;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.floragunn.searchguard.user.VXUser;

import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import java.net.URLClassLoader;
import java.net.URL;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;

public class PrivilegesEvaluator {

    private static final Set<String> NO_INDICES_SET = Sets.newHashSet("\\",";",",","/","|");
    private static final Set<String> NULL_SET = Sets.newHashSet((String)null);
    private final Set<String> DLSFLS = ImmutableSet.of("_dls_", "_fls_");
    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private final ClusterService clusterService;
    private final ActionGroupHolder ah;
    private final IndexNameExpressionResolver resolver;
    private final Map<Class<?>, Method> typeCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final Map<Class<?>, Method> typesCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final String[] sgDeniedActionPatterns;
    private final AuditLog auditLog;
    private ThreadContext threadContext;
    private final static IndicesOptions DEFAULT_INDICES_OPTIONS = IndicesOptions.lenientExpandOpen();
    private final ConfigurationRepository configurationRepository;

    private final String searchguardIndex;
    private PrivilegesInterceptor privilegesInterceptor;
    
    private final boolean enableSnapshotRestorePrivilege;
    private final boolean checkSnapshotRestoreWritePrivileges;
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;
    
    private final ClusterInfoHolder clusterInfoHolder;
    //private final boolean typeSecurityDisabled = false;
    public static final String ACCESS_TYPE_READ = "read";
    public static final String ACCESS_TYPE_WRITE = "write";
    public static final String ACCESS_TYPE_ADMIN = "es_admin";
    private static volatile RangerBasePlugin rangerPlugin = null;
    private String rangerUrl = null;
    private UserGroupMappingCache usrGrpCache = null;
    private boolean enabledFlag = false;
    private boolean initUGI = false;

    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool, final ConfigurationRepository configurationRepository, final ActionGroupHolder ah,
            final IndexNameExpressionResolver resolver, AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor,
            final ClusterInfoHolder clusterInfoHolder) {

        super();
        this.configurationRepository = configurationRepository;
        this.clusterService = clusterService;
        this.ah = ah;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        this.privilegesInterceptor = privilegesInterceptor;
        this.enableSnapshotRestorePrivilege = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                ConfigConstants.SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE);
        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);
        
        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(settings.get(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString()).toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution",e);
            rolesMappingResolution =  ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }
        
        final List<String> sgIndexdeniedActionPatternsList = new ArrayList<String>();
        sgIndexdeniedActionPatternsList.add("indices:data/write*");
        sgIndexdeniedActionPatternsList.add("indices:admin/close");
        sgIndexdeniedActionPatternsList.add("indices:admin/delete");
        //deniedActionPatternsList.add("indices:admin/settings/update");
        //deniedActionPatternsList.add("indices:admin/upgrade");
        
        sgDeniedActionPatterns = sgIndexdeniedActionPatternsList.toArray(new String[0]);
        this.clusterInfoHolder = clusterInfoHolder;
        //this.typeSecurityDisabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_DISABLE_TYPE_SECURITY, false);
        
        //Check if Ranger Authz is enabled
        
        enabledFlag = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTH_RANGER_ENABLED, false);
        String ES_PLUGIN_APP_ID = settings.get(ConfigConstants.SEARCHGUARD_AUTH_RANGER_APP_ID);
        
        if (ES_PLUGIN_APP_ID == null && enabledFlag) {
            throw new ElasticsearchSecurityException("Search Guard Ranger plugin enabled but appId config not valid");
        }
        
        if (!initializeUGI(settings)) {
            log.error("UGI not getting initialized.");
            /*
            if (enabledFlag) {
                throw new ElasticsearchSecurityException("Unable to initialize spnego client and UGI");
            }
            */
        }
        
        if (enabledFlag) {
            configureRangerPlugin(settings);
            usrGrpCache = new UserGroupMappingCache();
            usrGrpCache.init();
        }
    }
    
    public void configureRangerPlugin(Settings settings) {
        String svcType = settings.get(ConfigConstants.SEARCHGUARD_AUTH_RANGER_SERVICE_TYPE, "elasticsearch");
        String appId = settings.get(ConfigConstants.SEARCHGUARD_AUTH_RANGER_APP_ID);
        
        RangerBasePlugin me = rangerPlugin;
        if (me == null) {
            synchronized(PrivilegesEvaluator.class) {
                me = rangerPlugin;
                if (me == null) {
                    me = rangerPlugin = new RangerBasePlugin(svcType, appId);
                }    
            }
        }
        log.debug("Calling ranger plugin init");
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                ClassLoader cl = org.apache.ranger.authorization.hadoop.config.RangerConfiguration.class.getClassLoader();
                URL[] urls = ((URLClassLoader)cl).getURLs();
                String pluginPath = null;
                for(URL url: urls){
                    String urlFile = url.getFile();
                    int idx = urlFile.indexOf("ranger-plugins-common");
                    if (idx != -1) {
                        pluginPath = urlFile.substring(0, idx);
                    }
                }

                try {
                    Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[]{URL.class});
                    method.setAccessible(true);
                    String rangerResourcesPath = pluginPath + "resources/";
                    method.invoke(cl, new Object[]{new File(rangerResourcesPath).toURI().toURL()});
                } catch (Exception e) {
                    log.error("Error in adding ranger config files to classpath : " + e.getMessage());
                    if (log.isDebugEnabled()) {
                        e.printStackTrace();
                    }
                }
                rangerPlugin.init();
                return null;
            }
        });
        this.rangerUrl = RangerConfiguration.getInstance().get("ranger.plugin.elasticsearch.policy.rest.url");
        log.debug("Ranger uri : " + rangerUrl);
        RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
        rangerPlugin.setResultProcessor(auditHandler);
    }
    
    private Settings getRolesSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES);
    }

    private Settings getRolesMappingSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES_MAPPING);
    }
    
    private Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_CONFIG);
    }
    
    public boolean isInitialized() {
        return getRolesSettings() != null && getRolesMappingSettings() != null && getConfigSettings() != null;
    }

    public boolean initializeUGI(Settings settings) {
        if (initUGI) {
            return true;
        }
        
        String svcName = settings.get(ConfigConstants.SEARCHGUARD_KERBEROS_ACCEPTOR_PRINCIPAL);        
        String keytabPath = settings.get(ConfigConstants.SEARCHGUARD_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, 
                HTTPSpnegoAuthenticator.SERVER_KEYTAB_PATH);
        String krbConf = settings.get(ConfigConstants.SEARCHGUARD_KERBEROS_KRB5_FILEPATH, 
                HTTPSpnegoAuthenticator.KRB5_CONF);
        
        if (Strings.isNullOrEmpty(svcName)) {
            log.error("Acceptor kerberos principal is empty or null");
            return false;
        }
        
        HTTPSpnegoAuthenticator.initSpnegoClient(svcName, keytabPath, krbConf);
        
        SpnegoClient spnegoClient = HTTPSpnegoAuthenticator.getSpnegoClient();
        
        if (spnegoClient == null) {
            log.error("Spnego client not initialized");
            return false;
        }
        
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        initUGI = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                Subject subject = spnegoClient.getSubject();
        
                try {
                    UserGroupInformation ugi = MiscUtil.createUGIFromSubject(subject);
                    if (ugi != null) {
                        MiscUtil.setUGILoginUser(ugi, subject);
                    } else {
                        log.error("Unable to initialize UGI");
                        return false;
                    }
                } catch (Throwable t) {
                    log.error("Exception while trying to initialize UGI: " + t.getMessage());
                    return false;
                }
                return true;
            }
        });

        return initUGI;
    }

    public static class IndexType {

        private String index;
        private String type;

        public IndexType(String index, String type) {
            super();
            this.index = index;
            this.type = type.equals("_all")? "*": type;
        }

        public String getCombinedString() {
            return index+"#"+type;
        }

        public String getIndex() {
            return index;
        }

        public String getType() {
            return type;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((index == null) ? 0 : index.hashCode());
            result = prime * result + ((type == null) ? 0 : type.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            IndexType other = (IndexType) obj;
            if (index == null) {
                if (other.index != null)
                    return false;
            } else if (!index.equals(other.index))
                return false;
            if (type == null) {
                if (other.type != null)
                    return false;
            } else if (!type.equals(other.type))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "IndexType [index=" + index + ", type=" + type + "]";
        }
    }

    private static class IndexTypeAction extends IndexType {

        private String action;

        public IndexTypeAction(String index, String type, String action) {
            super(index, type);
            this.action = action;
        }

        @Override
        public String getCombinedString() {
            return super.getCombinedString()+"#"+action;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = super.hashCode();
            result = prime * result + ((action == null) ? 0 : action.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            if (!super.equals(obj))
                return false;
            IndexTypeAction other = (IndexTypeAction) obj;
            if (action == null) {
                if (other.action != null)
                    return false;
            } else if (!action.equals(other.action))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "IndexTypeAction [index=" + getIndex() + ", type=" + getType() + ", action=" + action + "]";
        }
    }

    public static class PrivEvalResponse {
        boolean allowed = false;
        Set<String> missingPrivileges = new HashSet<String>();
        Map<String,Set<String>> allowedFlsFields;
        Map<String,Set<String>> queries; 
        
        public boolean isAllowed() {
            return allowed;
        }
        public Set<String> getMissingPrivileges() {
            return new HashSet<String>(missingPrivileges);
        }
        
        public Map<String,Set<String>> getAllowedFlsFields() {
            return allowedFlsFields;
        }
        
        public Map<String,Set<String>> getQueries() {
            return queries;
        }
    }
    
    public PrivEvalResponse evaluate(final User user, String action, final ActionRequest request, Task task) {       
        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Search Guard is not initialized.");
        }
        
        final PrivEvalResponse presponse = new PrivEvalResponse();
        presponse.missingPrivileges.add(action);

        if (!enabledFlag) {
            //Ranger Authz disabled. Return from here
            presponse.allowed = true;
            return presponse;
        }

        usrGrpCache.setSettings(getConfigSettings());
        if (rangerPlugin == null) {
            log.error("Ranger Plugin not initialized");
            presponse.allowed = false;
            return presponse;
        }
             
        try {
            if(request instanceof SearchRequest) {
                SearchRequest sr = (SearchRequest) request;                
                if(     sr.source() != null
                        && sr.source().query() == null
                        && sr.source().aggregations() != null
                        && sr.source().aggregations().getAggregatorFactories() != null
                        && sr.source().aggregations().getAggregatorFactories().size() == 1 
                        && sr.source().size() == 0) {
                   AggregationBuilder ab = sr.source().aggregations().getAggregatorFactories().get(0);                   
                   if(     ab instanceof TermsAggregationBuilder 
                           && "terms".equals(ab.getType()) 
                           && "indices".equals(ab.getName())) {                       
                       if("_index".equals(((TermsAggregationBuilder) ab).field()) 
                               && ab.getPipelineAggregations().isEmpty() 
                               && ab.getSubAggregations().isEmpty()) {                  
                           presponse.allowed = true;
                           return presponse;
                       }
                   }
                }
            }
        } catch (Exception e) {
            log.warn("Unable to evaluate terms aggregation",e);
        }
        
        final TransportAddress caller = Objects.requireNonNull((TransportAddress) this.threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS));
        
        if (log.isDebugEnabled()) {
            log.debug("### evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("requested {} from {}", action, caller);
        }

        if(action.startsWith("internal:indices/admin/upgrade")) {
            action = "indices:admin/upgrade";
            //Add code for Ranger - Admin, _all
            String indexName = "_all";
            
        }

        final ClusterState clusterState = clusterService.state();
        final MetaData metaData = clusterState.metaData();

        final Tuple<Set<String>, Set<String>> requestedResolvedAliasesIndicesTypes = resolve(user, action, request, metaData);
                
        final SortedSet<String> requestedResolvedIndices = Collections.unmodifiableSortedSet(new TreeSet<>(requestedResolvedAliasesIndicesTypes.v1()));        
        final Set<IndexType> requestedResolvedIndexTypes;
        
        {
            final Set<IndexType> requestedResolvedIndexTypes0 = new HashSet<IndexType>(requestedResolvedAliasesIndicesTypes.v1().size() * requestedResolvedAliasesIndicesTypes.v2().size());
            
            for(String index: requestedResolvedAliasesIndicesTypes.v1()) {
                for(String type: requestedResolvedAliasesIndicesTypes.v2()) {
                    requestedResolvedIndexTypes0.add(new IndexType(index, type));
                }
            }
            
            requestedResolvedIndexTypes = Collections.unmodifiableSet(requestedResolvedIndexTypes0);
        }
        
        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolvedIndexTypes);
        }

        boolean allowAction = false;
        
        final Map<String, Set<IndexType>> leftovers = new HashMap<String, Set<IndexType>>();
        
        //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();
        Set<String> indices = new HashSet<String>();
        Set<String> types = new HashSet<String>();

        log.debug("Action requested: " + action);

        if (request instanceof BulkShardRequest) {
            log.debug("BulkShardRequest");
            final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
            indices.addAll(t.v1());
            types.addAll(t.v2());
            allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
            presponse.allowed = allowAction;
            
            if (!allowAction) {
                log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
            }
            
            return presponse;

        }
        
        
        if(request instanceof PutMappingRequest) {
            
                log.debug("PutMappingRequest");
            
            PutMappingRequest pmr = (PutMappingRequest) request;
            Index concreteIndex = pmr.getConcreteIndex();
            
            if(concreteIndex != null && (pmr.indices() == null || pmr.indices().length == 0)) {
                String indexName = concreteIndex.getName();
                //Add code for Ranger - Admin
                indices.clear();
                indices.add(indexName);
                allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
            }
        }

        
        if (!(request instanceof CompositeIndicesRequest) 
                && !(request instanceof IndicesRequest)
                && !(request instanceof IndicesAliasesRequest)) {

                log.debug("Request class is {}", request.getClass());
            //Add code for Ranger - Admin
            indices.clear();
            indices.add("_all");
        } else if (request instanceof IndicesAliasesRequest) {
            log.debug("IndicesAliasesRequest");
            
            for(AliasActions ar: ((IndicesAliasesRequest) request).getAliasActions()) {
                final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, ar, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
            }
            //Add code for Ranger - Admin
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin") ;
            presponse.allowed = allowAction;
            
            if (!allowAction) {
                log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
            }
            
            return presponse;
            
        } else if (request instanceof CompositeIndicesRequest) {
            log.debug("CompositeIndicesRequest");

            if(request instanceof IndicesRequest) {
                log.debug("IndicesRequest");


                final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof BulkRequest) || (action.equals(BulkAction.NAME)) ) {
                log.debug("BulkRequest");

                for(DocWriteRequest<?> ar: ((BulkRequest) request).requests()) {
                    
                    //TODO SG6 require also op type permissions
                    //require also op type permissions
                    //ar.opType()
                   
                    final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - write
 
                }
                allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof MultiGetRequest) || (action.equals(MultiGetAction.NAME))) {
                log.debug("MultiGetRequest");

                for(Item item: ((MultiGetRequest) request).getItems()) {
                    final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, item, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - READ
                }
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof MultiSearchRequest) || (action.equals(MultiSearchAction.NAME))) {
                log.debug("MultiSearchRequest");

                for(ActionRequest ar: ((MultiSearchRequest) request).requests()) {
                    final Tuple<Set<String>, Set<String>> t = resolve(user, action, ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - READ
                }
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof MultiTermVectorsRequest) || (action.equals(MultiTermVectorsAction.NAME))) {
                log.debug("MultiTermVectorsRequest");

                for(ActionRequest ar: (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
                    final Tuple<Set<String>, Set<String>> t = resolve(user, action, ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - Read
                }
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof ReindexRequest) || (action.equals(ReindexAction.NAME))) {
                log.debug("ReindexRequest");

                ReindexRequest reindexRequest = (ReindexRequest) request;
                Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, reindexRequest.getDestination(), metaData);
                indices.clear();
                indices.addAll(t.v1());
                types.addAll(t.v2());
                allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
                if (!allowAction) {
                    presponse.allowed = allowAction;
                    
                    if (!allowAction) {
                        log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                    }
                    
                    return presponse;
                }
                
                t = resolveIndicesRequest(user, action, reindexRequest.getSearchRequest(), metaData);
                indices.clear();
                indices.addAll(t.v1());
                types.addAll(t.v2());
                //Add code for Ranger - Admin
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
            } else {
                log.debug("Can not handle request of type '"+request.getClass().getName()+"'for "+action+" here");
            }

        } else {
            //ccs goes here
            final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
            indices = t.v1();
            types = t.v2();
        }
                        
        log.debug("Action requested: " + action + " , indices: " + String.join(",", indices));
        if (action.startsWith("cluster:monitor/")) {
            indices.clear();
            indices.add("_cluster");
            allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
        } else if (action.startsWith("cluster:")) {
            /* Not clear on following so skipping:
             *             || action.startsWith(SearchScrollAction.NAME)
             *              || (action.equals("indices:data/read/coordinate-msearch"))
             */
            indices.clear();
            indices.add("_cluster");
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin");
        } else if (action.startsWith("indices:admin/create")
                || (action.startsWith("indices:admin/mapping/put"))) {
            
            allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
        } else if ((action.startsWith("indices:data/read"))
                || (action.startsWith("indices:monitor/"))
                || (action.startsWith("indices:admin/template/get"))
                || (action.startsWith("indices:admin/mapping/get"))
                || (action.startsWith("indices:admin/mappings/get"))
                || (action.startsWith("indices:admin/mappings/fields/get"))
                || (action.startsWith("indices:admin/aliases/exists"))
                || (action.startsWith("indices:admin/aliases/get"))
                || (action.startsWith("indices:admin/exists"))
                || (action.startsWith("indices:admin/get"))){
            //Add code for Ranger - Read
            allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
        } else if (action.startsWith("indices:data/write")
                || (action.startsWith("indices:data/"))) {
            //Add code for Ranger - Write/Delete
            allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
        } else if (action.startsWith("indices:")) {
            log.debug("All remaining unknown actions with indices:");

            //Add code for Ranger - Admin
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin"); 
        } else {
            log.debug("All remaining unknown actions");
            indices.clear();
            indices.add("_cluster");
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin");
        }

        if (!allowAction) {
            log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
        }
        presponse.allowed = allowAction;
        return presponse;        
    }
    

    private boolean checkRangerAuthorization(final User user, TransportAddress caller, String accessType, Set<String> indices, String clusterLevelAccessType) {
        //String clusterName = rangerPlugin.getClusterName();
        boolean checkClusterLevelPermission = false;
        Date eventTime = new Date();
        String ipAddress = caller.address().getHostString();
        RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
        rangerRequest.setUser(user.getName());
        
        Set<String> userGroups = null;
        Set<String> userRoles = user.getRoles();
        if (userRoles != null && !(userRoles.isEmpty())) {
            userGroups = userRoles;
        } else {
            try {
                SecurityManager sm = System.getSecurityManager();
                if (sm != null) {
                    sm.checkPermission(new SpecialPermission());
                }
            
                userGroups = AccessController.doPrivileged(new PrivilegedAction<Set<String>>() {
                    public Set<String> run() {
                        try {
                            return usrGrpCache.getUserGroups(user.getName());
                        } catch (Exception e) {
                            if (log.isDebugEnabled()) {
                                e.printStackTrace();
                            }
                            log.warn("Exception in retrieving user group mapping : " + e.getMessage() );
                        }
                        return null;
                    }
                });
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    e.printStackTrace();
                }
                log.warn("Exception in retrieving user group mapping : " + e.getMessage() );
            }
        }
        
        if (userGroups != null) {
            rangerRequest.setUserGroups(userGroups);
        } else {
            log.warn("No groups found for user : " + user.getName());
        }
        rangerRequest.setClientIPAddress(ipAddress);
        rangerRequest.setAccessTime(eventTime);
        RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
        rangerRequest.setResource(rangerResource);
        rangerRequest.setAccessType(accessType);
        rangerRequest.setAction(accessType);
        //rangerRequest.setClusterName(clusterName);
        
        for (Iterator<String> it = indices.iterator(); it.hasNext();) {
            String index = it.next();
            log.debug("Checking for index: " + index + ", for user: " + user.getName() + " and accessType: " + accessType);
            rangerResource.setValue("index", index);
            RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
            if (result == null || !(result.getIsAllowed())) {
                if ((!index.equals("_all")) && (!index.equals("_cluster"))) {
                    checkClusterLevelPermission = true;
                } else {
                    log.debug("Index/Cluster Permission denied");
                    return false;
                }
            }
        }
        if (checkClusterLevelPermission) {
            log.debug("Checking all level permissions (_all), accessType: " + clusterLevelAccessType);
            rangerResource.setValue("index", "_all");
            rangerRequest.setAccessType(clusterLevelAccessType);
            RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
            if (result == null || !(result.getIsAllowed())) {
                log.debug("All level Permission denied");
                return false;
            }
        }
        return true;
    }
    
     
    //---- end evaluate()
    
    private PrivEvalResponse evaluateSnapshotRestore(final User user, String action, final ActionRequest request, final TransportAddress caller, final Task task) {
        
        final PrivEvalResponse presponse = new PrivEvalResponse();
        presponse.missingPrivileges.add(action);
        
        if (!(request instanceof RestoreSnapshotRequest)) {
            return presponse;
        }

        final RestoreSnapshotRequest restoreRequest = (RestoreSnapshotRequest) request;

        // Do not allow restore of global state
        if (restoreRequest.includeGlobalState()) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " with 'include_global_state' enabled is not allowed");
            return presponse;
        }

        // Start resolve for RestoreSnapshotRequest
        final RepositoriesService repositoriesService = Objects.requireNonNull(SearchGuardPlugin.GuiceHolder.getRepositoriesService(), "RepositoriesService not initialized");     
        //hack, because it seems not possible to access RepositoriesService from a non guice class
        final Repository repository = repositoriesService.repository(restoreRequest.repository());
        SnapshotInfo snapshotInfo = null;

        for (final SnapshotId snapshotId : repository.getRepositoryData().getSnapshotIds()) {
            if (snapshotId.getName().equals(restoreRequest.snapshot())) {

                if(log.isDebugEnabled()) {
                    log.info("snapshot found: {} (UUID: {})", snapshotId.getName(), snapshotId.getUUID());    
                }

                snapshotInfo = repository.getSnapshotInfo(snapshotId);
                break;
            }
        }

        if (snapshotInfo == null) {
            log.warn(action + " for repository '" + restoreRequest.repository() + "', snapshot '" + restoreRequest.snapshot() + "' not found");
            return presponse;
        }

        final List<String> requestedResolvedIndices = SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());

        if (log.isDebugEnabled()) {
            log.info("resolved indices for restore to: {}", requestedResolvedIndices.toString());
        }
        // End resolve for RestoreSnapshotRequest

        // Check if the source indices contain the searchguard index
        if (requestedResolvedIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as source index is not allowed", searchguardIndex);
            return presponse;
        }

        // Check if the renamed destination indices contain the searchguard index
        final List<String> renamedTargetIndices = renamedIndices(restoreRequest, requestedResolvedIndices);
        if (renamedTargetIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as target index is not allowed", searchguardIndex);
            return presponse;
        }

        // Check if the user has the required role to perform the snapshot restore operation
        final Set<String> sgRoles = mapSgRoles(user, caller);

        if (log.isDebugEnabled()) {
            log.info("mapped roles: {}", sgRoles);
        }

        boolean allowedActionSnapshotRestore = false;

        final Set<String> renamedTargetIndicesSet = new HashSet<String>(renamedTargetIndices);
        final Set<IndexType> _renamedTargetIndices = new HashSet<IndexType>(renamedTargetIndices.size());
        for(final String index: renamedTargetIndices) {
            for(final String neededAction: ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES) {
                _renamedTargetIndices.add(new IndexTypeAction(index, "*", neededAction));
            }
        }
        
        final Settings roles = getRolesSettings();

        for (final Iterator<String> iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = iterator.next();
            final Settings sgRoleSettings = roles.getByPrefix(sgRole);

            if (sgRoleSettings.names().isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("sg_role {} is empty", sgRole);
                }

                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("---------- evaluate sg_role: {}", sgRole);
            }

            final Set<String> resolvedActions = resolveActions(sgRoleSettings.getAsList(".cluster", Collections.emptyList()));
            if (log.isDebugEnabled()) {
                log.debug("  resolved cluster actions:{}", resolvedActions);
            }

            if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                if (log.isDebugEnabled()) {
                    log.debug("  found a match for '{}' and {}, skip other roles", sgRole, action);
                }
                allowedActionSnapshotRestore = true;
            } else {
                // check other roles #108
                if (log.isDebugEnabled()) {
                    log.debug("  not match found a match for '{}' and {}, check next role", sgRole, action);
                }
            }

            if (checkSnapshotRestoreWritePrivileges) {
                final Map<String, Settings> permittedAliasesIndices0 = sgRoleSettings.getGroups(".indices", true);
                final Map<String, Settings> permittedAliasesIndices = new HashMap<String, Settings>(permittedAliasesIndices0.size());

                for (final String origKey : permittedAliasesIndices0.keySet()) {
                    permittedAliasesIndices.put(replaceProperties(origKey, user), permittedAliasesIndices0.get(origKey));
                }

                for (final String permittedAliasesIndex : permittedAliasesIndices.keySet()) {
                    if (log.isDebugEnabled()) {
                        log.debug("  Try wildcard match for {}", permittedAliasesIndex);
                    }

                    handleSnapshotRestoreWritePrivileges(ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES, permittedAliasesIndex, permittedAliasesIndices, renamedTargetIndicesSet, _renamedTargetIndices);

                    if (log.isDebugEnabled()) {
                        log.debug("For index {} remaining requested indextypeaction: {}", permittedAliasesIndex, _renamedTargetIndices);
                    }

                }// end loop permittedAliasesIndices
            }
        }

        if (checkSnapshotRestoreWritePrivileges && !_renamedTargetIndices.isEmpty()) {
            allowedActionSnapshotRestore = false;
        }

        if (!allowedActionSnapshotRestore) {
            auditLog.logMissingPrivileges(action, request, task);
            log.debug("No perm match for {} [Action [{}]] [RolesChecked {}]", user, action, sgRoles);
        }
        
        presponse.allowed = allowedActionSnapshotRestore;
        return presponse;
    }

    private List<String> renamedIndices(final RestoreSnapshotRequest request, final List<String> filteredIndices) {
        final List<String> renamedIndices = new ArrayList<>();
        for (final String index : filteredIndices) {
            String renamedIndex = index;
            if (request.renameReplacement() != null && request.renamePattern() != null) {
                renamedIndex = index.replaceAll(request.renamePattern(), request.renameReplacement());
            }
            renamedIndices.add(renamedIndex);
        }
        return renamedIndices;
    }

    public Set<String> mapSgRoles(final User user, final TransportAddress caller) {
        
        final Settings rolesMapping = getRolesMappingSettings();
        final Set<String> sgRoles = new TreeSet<String>();
        
        if(user == null) {
            return Collections.emptySet();
        }
        
        if(rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
            if(log.isDebugEnabled()) {
                log.debug("Pass backendroles from {}", user);
            }
            sgRoles.addAll(user.getRoles());
        }
        
        if(rolesMapping != null && ((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH 
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {
            for (final String roleMap : rolesMapping.names()) {
                final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);
                
                if (WildcardMatcher.allPatternsMatched(roleMapSettings.getAsList(".and_backendroles", Collections.emptyList()).toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap);
                    continue;
                }
                
                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".backendroles", Collections.emptyList()).toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".users"), user.getName())) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (caller != null &&  WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), caller.getAddress())) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (caller != null && WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), caller.getAddress())) {
                    sgRoles.add(roleMap);
                    continue;
                }

            }
        }

        return Collections.unmodifiableSet(sgRoles);

    }
    
    public Map<String, Boolean> mapTenants(final User user, final TransportAddress caller) {
        
        if(user == null) {
            return Collections.emptyMap();
        }
        
        final Map<String, Boolean> result = new HashMap<String, Boolean>();
        result.put(user.getName(), true);
        
        for(String sgRole: mapSgRoles(user, caller)) {
            Settings tenants = getRolesSettings().getByPrefix(sgRole+".tenants.");
            
            if(tenants != null) {
                for(String tenant: tenants.names()) {
                    
                    if(tenant.equals(user.getName())) {
                        continue;
                    }
                    
                    if("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                        result.put(tenant, true);
                    } else {
                        if(!result.containsKey(tenant)) { //RW outperforms RO
                            result.put(tenant, false);
                        }
                    }
                }
            }
            
        }

        return Collections.unmodifiableMap(result);
    }


    private void handleIndicesWithWildcard(final String[] action0, final String permittedAliasesIndex,
            final Map<String, Settings> permittedAliasesIndices, final Set<IndexType> requestedResolvedIndexTypes, final Set<IndexType> _requestedResolvedIndexTypes, final Set<String> requestedResolvedIndices0) {
        
        List<String> wi = null;
        if (!(wi = WildcardMatcher.getMatchAny(permittedAliasesIndex, requestedResolvedIndices0.toArray(new String[0]))).isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("  Wildcard match for {}: {}", permittedAliasesIndex, wi);
            }

            final Set<String> permittedTypes = new HashSet<String>(permittedAliasesIndices.get(permittedAliasesIndex).names());
            permittedTypes.removeAll(DLSFLS);
            
            if (log.isDebugEnabled()) {
                log.debug("  matches for {}, will check now types {}", permittedAliasesIndex, permittedTypes);
            }

            for (final String type : permittedTypes) {
                
                final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsList(type));

                if (WildcardMatcher.matchAll(resolvedActions.toArray(new String[0]), action0)) {
                    if (log.isDebugEnabled()) {
                        log.debug("    match requested action {} against {}/{}: {}", action0, permittedAliasesIndex, type, resolvedActions);
                    }

                    for(String it: wi) {
                        boolean removed = wildcardRemoveFromSet(_requestedResolvedIndexTypes, new IndexType(it, type));
                        
                        if(removed) {
                            log.debug("    removed {}", it+type);
                        } else {
                            log.debug("    no match {} in {}", it+type, _requestedResolvedIndexTypes);
                        }
                    }
                }
                
            }  
        } else {
            if (log.isDebugEnabled()) {
                log.debug("  No wildcard match found for {}", permittedAliasesIndex);
            }

            return;
        }
    }

    private void handleIndicesWithoutWildcard(final String[] action0, final String permittedAliasesIndex,
            final Map<String, Settings> permittedAliasesIndices, final Set<IndexType> requestedResolvedIndexTypes, final Set<IndexType> _requestedResolvedIndexTypes) {

        final Set<String> resolvedPermittedAliasesIndex = new HashSet<String>();
        
        if(!resolver.hasIndexOrAlias(permittedAliasesIndex, clusterService.state())) {
            
            if(log.isDebugEnabled()) {
                log.debug("no permittedAliasesIndex '{}' found for  '{}'", permittedAliasesIndex,  action0);
                
                
                for(String pai: permittedAliasesIndices.keySet()) {
                    Settings paiSettings = permittedAliasesIndices.get(pai);
                    log.debug("permittedAliasesIndices '{}' -> '{}'", permittedAliasesIndices, paiSettings==null?"null":String.valueOf(paiSettings));
                }
                
                log.debug("requestedResolvedIndexTypes '{}'", requestedResolvedIndexTypes);   
            }
            
            resolvedPermittedAliasesIndex.add(permittedAliasesIndex);

        } else {

            resolvedPermittedAliasesIndex.addAll(Arrays.asList(resolver.concreteIndexNames(
                    clusterService.state(), DEFAULT_INDICES_OPTIONS, permittedAliasesIndex)));
        }

        if (log.isDebugEnabled()) {
            log.debug("  resolved permitted aliases indices for {}: {}", permittedAliasesIndex, resolvedPermittedAliasesIndex);
        }

        //resolvedPermittedAliasesIndex -> resolved indices from role entry n
        final Set<String> permittedTypes = new HashSet<String>(permittedAliasesIndices.get(permittedAliasesIndex).names());
        permittedTypes.removeAll(DLSFLS);
        
        if (log.isDebugEnabled()) {
            log.debug("  matches for {}, will check now types {}", permittedAliasesIndex, permittedTypes);
        }

        for (final String type : permittedTypes) {
            
            final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsList(type));

            if (WildcardMatcher.matchAll(resolvedActions.toArray(new String[0]), action0)) {
                if (log.isDebugEnabled()) {
                    log.debug("    match requested action {} against {}/{}: {}", action0, permittedAliasesIndex, type, resolvedActions);
                }

                for(String resolvedPermittedIndex: resolvedPermittedAliasesIndex) {
                    boolean removed = wildcardRemoveFromSet(_requestedResolvedIndexTypes, new IndexType(resolvedPermittedIndex, type));
                    
                    if(removed) {
                        log.debug("    removed {}", resolvedPermittedIndex+type);

                    } else {
                        log.debug("    no match {} in {}", resolvedPermittedIndex+type, _requestedResolvedIndexTypes);
                    }
                }
            }
        }
    }

    private void handleSnapshotRestoreWritePrivileges(final Set<String> actions, final String permittedAliasesIndex,
                                              final Map<String, Settings> permittedAliasesIndices, final Set<String> requestedResolvedIndices, final Set<IndexType> requestedResolvedIndices0) {
        List<String> wi = null;
        if (!(wi = WildcardMatcher.getMatchAny(permittedAliasesIndex, requestedResolvedIndices.toArray(new String[0]))).isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("  Wildcard match for {}: {}", permittedAliasesIndex, wi);
            }

            // Get actions only for the catch all wildcard type '*'
            final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsList("*"));

            if (log.isDebugEnabled()) {
                log.debug("  matches for {}, will check now wildcard type '*'", permittedAliasesIndex);
            }

            //TODO check wa var
            List<String> wa = null;
            for (String at : resolvedActions) {
                if (!(wa = WildcardMatcher.getMatchAny(at, actions.toArray(new String[0]))).isEmpty()) {
                    if (log.isDebugEnabled()) {
                        log.debug("    match requested actions {} against {}/*: {}", actions, permittedAliasesIndex, resolvedActions);
                    }

                    for (String it : wi) {
                        boolean removed = wildcardRemoveFromSet(requestedResolvedIndices0, new IndexTypeAction(it, "*", at));

                        if (removed) {
                            log.debug("    removed {}", it + '*');
                        } else {
                            log.debug("    no match {} in {}", it + '*', requestedResolvedIndices0);
                        }

                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("  No wildcard match found for {}", permittedAliasesIndex);
            }
        }
    }

    private Tuple<Set<String>, Set<String>> resolve(final User user, final String action, final TransportRequest request,
            final MetaData metaData) {
        
        if(request instanceof PutMappingRequest) {
            
            if (log.isDebugEnabled()) {
                log.debug("PutMappingRequest will be handled in a "
                        + "special way cause they does not return indices via .indices()"
                        + "Instead .getConcreteIndex() must be used");
            }
            
            PutMappingRequest pmr = (PutMappingRequest) request;
            Index concreteIndex = pmr.getConcreteIndex();
            
            if(concreteIndex != null && (pmr.indices() == null || pmr.indices().length == 0)) {
                return new Tuple<Set<String>, Set<String>>(Sets.newHashSet(concreteIndex.getName()), Sets.newHashSet(pmr.type()));
            }
        }


        if (!(request instanceof CompositeIndicesRequest) 
                && !(request instanceof IndicesRequest)
                && !(request instanceof IndicesAliasesRequest)) {

            if (log.isDebugEnabled()) {
                log.debug("{} is not an IndicesRequest", request.getClass());
            }
            if (action.startsWith("cluster:")) {
                return new Tuple<Set<String>, Set<String>>(Sets.newHashSet("_cluster"), Sets.newHashSet("_all"));
            }
            return new Tuple<Set<String>, Set<String>>(Sets.newHashSet("_all"), Sets.newHashSet("_all"));
        }
        
        Set<String> indices = new HashSet<String>();
        Set<String> types = new HashSet<String>();
        
        if (request instanceof IndicesAliasesRequest) {
            
            for(AliasActions ar: ((IndicesAliasesRequest) request).getAliasActions()) {
                final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, ar, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
            }
            
        } else if (request instanceof CompositeIndicesRequest) {

            if(request instanceof IndicesRequest) { //skip BulkShardRequest?

                final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
                
            } else if(request instanceof BulkRequest) {
                
                for(DocWriteRequest<?> ar: ((BulkRequest) request).requests()) {
                    
                    //TODO SG6 require also op type permissions
                    //require also op type permissions
                    //ar.opType()
                    
                    final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                }
                
            } else if(request instanceof MultiGetRequest) {
                
                for(Item item: ((MultiGetRequest) request).getItems()) {
                    final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, item, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                }
                
            } else if(request instanceof MultiSearchRequest) {
                
                for(ActionRequest ar: ((MultiSearchRequest) request).requests()) {
                    final Tuple<Set<String>, Set<String>> t = resolve(user, action, ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                }
                
            } else if(request instanceof MultiTermVectorsRequest) {
                
                for(ActionRequest ar: (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
                    final Tuple<Set<String>, Set<String>> t = resolve(user, action, ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                }
                
                
            } else if(request instanceof ReindexRequest) {
                ReindexRequest reindexRequest = (ReindexRequest) request;
                Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, reindexRequest.getDestination(), metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
                
                t = resolveIndicesRequest(user, action, reindexRequest.getSearchRequest(), metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
            } else {
                log.error("Can not handle composite request of type '"+request.getClass().getName()+"'for "+action+" here");
            }

        } else {
            //ccs goes here
            final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
            indices = t.v1();
            types = t.v2();
        }
        
        if(log.isDebugEnabled()) {
            log.debug("pre final indices: {}", indices);
            log.debug("pre final types: {}", types);
        }
        
        if(indices == NO_INDICES_SET) {
            return new Tuple<Set<String>, Set<String>>(Collections.emptySet(), Collections.unmodifiableSet(types));
        }
        
        //for PutIndexTemplateRequest the index does not exists yet typically
        if (IndexNameExpressionResolver.isAllIndices(new ArrayList<String>(indices))) {
            if(log.isDebugEnabled()) {
                log.debug("The following list are '_all' indices: {}", indices);
            }
            
            //fix https://github.com/floragunncom/search-guard/issues/332
            if(!indices.isEmpty()) {
                indices.clear();
                indices.add("_all");
            }
        }

        if (types.isEmpty()) {
            types.add("_all");
        }
        
        if(log.isDebugEnabled()) {
            log.debug("final indices: {}", indices);
            log.debug("final types: {}", types);
        }
        return new Tuple<Set<String>, Set<String>>(Collections.unmodifiableSet(indices), Collections.unmodifiableSet(types));
    }

    private Tuple<Set<String>, Set<String>> resolveIndicesRequest(final User user, final String action, final IndicesRequest request,
            final MetaData metaData) {

        if (log.isDebugEnabled()) {
            log.debug("Resolve {} from {} for action {}", request.indices(), request.getClass(), action);
        }
        
        
        //TODO SG6 disable type security
        //final Boolean has5xIndices = clusterInfoHolder.getHas5xIndices();
        //final boolean fiveXIndicesPresent = has5xIndices == null || has5xIndices == Boolean.TRUE;

        final Class<? extends IndicesRequest> requestClass = request.getClass();
        final Set<String> requestTypes = new HashSet<String>();
        
        //if(fiveXIndicesPresent && !typeSecurityDisabled) {
        if(true) {
            Method typeMethod = null;
            if(typeCache.containsKey(requestClass)) {
                typeMethod = typeCache.get(requestClass);
            } else {
                try {
                    typeMethod = requestClass.getMethod("type");
                    typeCache.put(requestClass, typeMethod);
                } catch (NoSuchMethodException e) {
                    typeCache.put(requestClass, null);
                } catch (SecurityException e) {
                    log.error("Cannot evaluate type() for {} due to {}", requestClass, e, e);
                }
                
            }
            
            Method typesMethod = null;
            if(typesCache.containsKey(requestClass)) {
                typesMethod = typesCache.get(requestClass);
            } else {
                try {
                    typesMethod = requestClass.getMethod("types");
                    typesCache.put(requestClass, typesMethod);
                } catch (NoSuchMethodException e) {
                    typesCache.put(requestClass, null);
                } catch (SecurityException e) {
                    log.error("Cannot evaluate types() for {} due to {}", requestClass, e, e);
                }
                
            }
            
            if(typeMethod != null) {
                try {
                    String type = (String) typeMethod.invoke(request);
                    if(type != null) {
                        requestTypes.add(type);
                    }
                } catch (Exception e) {
                    log.error("Unable to invoke type() for {} due to", requestClass, e);
                }
            }
            
            if(typesMethod != null) {
                try {
                    final String[] types = (String[]) typesMethod.invoke(request);
                    
                    if(types != null) {
                        requestTypes.addAll(Arrays.asList(types));
                    }
                } catch (Exception e) {
                    log.error("Unable to invoke types() for {} due to", requestClass, e);
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("indicesOptions {}", request.indicesOptions());
            log.debug("{} raw indices {}", request.indices()==null?0:request.indices().length, Arrays.toString(request.indices()));
            log.debug("{} requestTypes {}", requestTypes.size(), requestTypes);
        }

        final Set<String> indices = new HashSet<String>();

        if(request.indices() == null || request.indices().length == 0 || new HashSet<String>(Arrays.asList(request.indices())).equals(NULL_SET)) {
            
            if(log.isDebugEnabled()) {
                log.debug("No indices found in request, assume _all");
            }

            indices.addAll(Arrays.asList(resolver.concreteIndexNames(clusterService.state(), DEFAULT_INDICES_OPTIONS, "*")));
            
        } else {
            
            String[] localIndices = request.indices();
            
            if(request instanceof FieldCapabilitiesRequest || request instanceof SearchRequest) {
                IndicesRequest.Replaceable searchRequest = (IndicesRequest.Replaceable) request;
                final Map<String, OriginalIndices> remoteClusterIndices = SearchGuardPlugin.GuiceHolder.getRemoteClusterService()
                        .groupIndices(searchRequest.indicesOptions(),searchRequest.indices(), idx -> resolver.hasIndexOrAlias(idx, clusterService.state()));
                                
                if (remoteClusterIndices.size() > 1) {
                    // check permissions?

                    final OriginalIndices originalLocalIndices = remoteClusterIndices.get(RemoteClusterAware.LOCAL_CLUSTER_GROUP_KEY);
                    localIndices = originalLocalIndices.indices();
                    
                    if (log.isDebugEnabled()) {
                        log.debug("remoteClusterIndices keys" + remoteClusterIndices.keySet() + "//remoteClusterIndices "
                                + remoteClusterIndices);
                    }
                    
                    if(localIndices.length == 0) {
                        return new Tuple<Set<String>, Set<String>>(NO_INDICES_SET, requestTypes);
                    }
                }
            }

            try { 
                final String[] dateMathIndices;
                if((dateMathIndices = WildcardMatcher.matches("<*>", localIndices, false)).length > 0) {
                    //date math
                    
                    if(log.isDebugEnabled()) {
                        log.debug("Date math indices detected {} (all: {})", dateMathIndices, localIndices);
                    }
                    
                    for(String dateMathIndex: dateMathIndices) {
                        indices.addAll(Arrays.asList(resolver.resolveDateMathExpression(dateMathIndex)));
                    }
                    
                    if(log.isDebugEnabled()) {
                        log.debug("Resolved date math indices {} to {}", dateMathIndices, indices);
                    }
                    
                    if(localIndices.length > dateMathIndices.length) {
                        for(String nonDateMath: localIndices) {
                            if(!WildcardMatcher.match("<*>", nonDateMath)) {
                                indices.addAll(Arrays.asList(resolver.concreteIndexNames(clusterService.state(), request.indicesOptions(), dateMathIndices)));
                            }
                        }
                        
                        if(log.isDebugEnabled()) {
                            log.debug("Resolved additional non date math indices {} to {}", localIndices, indices);
                        }
                    }

                } else {
                    
                    if(log.isDebugEnabled()) {
                        log.debug("No date math indices found");
                    }
                    
                    indices.addAll(Arrays.asList(resolver.concreteIndexNames(clusterService.state(), request.indicesOptions(), localIndices)));
                    if(log.isDebugEnabled()) {
                        log.debug("Resolved {} to {}", localIndices, indices);
                    }
                }                
            } catch (final Exception e) {
                log.debug("Cannot resolve {} (due to {}) so we use the raw values", Arrays.toString(localIndices), e);
                indices.addAll(Arrays.asList(localIndices));
            }
        }
        
        return new Tuple<Set<String>, Set<String>>(indices, requestTypes);
    }

    private Set<String> resolveActions(final List<String> actions) {
        final Set<String> resolvedActions = new HashSet<String>();
        for (String string: actions) {
            final Set<String> groups = ah.getGroupMembers(string);
            if (groups.isEmpty()) {
                resolvedActions.add(string);
            } else {
                resolvedActions.addAll(groups);
            }
        }

        return resolvedActions;
    }
    
    private boolean wildcardRemoveFromSet(Set<IndexType> set, IndexType stringContainingWc) {
        if(set.contains(stringContainingWc)) {
            return set.remove(stringContainingWc);
        } else {
            boolean modified = false;
            Set<IndexType> copy = new HashSet<IndexType>(set);
            
            for(IndexType it: copy) {
                if(WildcardMatcher.match(stringContainingWc.getCombinedString(), it.getCombinedString())) {
                    modified = set.remove(it) || modified;
                }
            }
            return modified;
        }  
    }
    
    private List<String> toString(List<AliasMetaData> aliases) {
        if(aliases == null || aliases.size() == 0) {
            return Collections.emptyList();
        }
        
        final List<String> ret = new ArrayList<String>(aliases.size());
        
        for(final AliasMetaData amd: aliases) {
            if(amd != null) {
                ret.add(amd.alias());
            }
        }
        
        return Collections.unmodifiableList(ret);
    }
    
    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class 
                && getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.multitenancy_enabled", true);
    }
    
    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.do_not_fail_on_forbidden", false);
    }
    
    public String kibanaIndex() {
        return getConfigSettings().get("searchguard.dynamic.kibana.index",".kibana");
    }
    
    public String kibanaServerUsername() {
        return getConfigSettings().get("searchguard.dynamic.kibana.server_username","kibanaserver");
    }
    
    public boolean kibanaIndexReadonly(final User user, final TransportAddress caller) {
        final Set<String> sgRoles = mapSgRoles(user, caller);
        
        final String kibanaIndex = kibanaIndex();
        
        for (final Iterator<String> iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = iterator.next();
            final Settings sgRoleSettings = getRolesSettings().getByPrefix(sgRole);
            
            if (sgRoleSettings.names().isEmpty()) {
                continue;
            }

            final Map<String, Settings> permittedAliasesIndices0 = sgRoleSettings.getGroups(".indices", true);
            final Map<String, Settings> permittedAliasesIndices = new HashMap<String, Settings>(permittedAliasesIndices0.size());

            for (String origKey : permittedAliasesIndices0.keySet()) {
               permittedAliasesIndices.put(replaceProperties(origKey, user), permittedAliasesIndices0.get(origKey));
            }
            
            for(String indexPattern: permittedAliasesIndices.keySet()) {                
                if(WildcardMatcher.match(indexPattern, kibanaIndex)) {
                    final Settings innerSettings = permittedAliasesIndices.get(indexPattern);
                    final List<String> perms = innerSettings.getAsList("*");
                    if(perms!= null && perms.size() > 0) {
                        if(WildcardMatcher.matchAny(resolveActions(perms).toArray(new String[0]), "indices:data/write/update")) {
                            return false;
                        }
                    }
                }
            }
        }

        return true;
    }
    
    private static String replaceProperties(String orig, User user) {
        orig = orig.replace("${user.name}", user.getName()).replace("${user_name}", user.getName());
        for(Entry<String, String> entry: user.getCustomAttributesMap().entrySet()) {
            if(entry == null || entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            orig = orig.replace("${"+entry.getKey()+"}", entry.getValue());
            orig = orig.replace("${"+entry.getKey().replace('.', '_')+"}", entry.getValue());
        }
        return orig;
    }
}
