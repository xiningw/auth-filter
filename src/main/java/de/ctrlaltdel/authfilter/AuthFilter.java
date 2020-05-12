package de.ctrlaltdel.authfilter;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.security.impl.BasicAuthenticationMechanism;
import io.undertow.security.impl.SecurityContextImpl;
import io.undertow.server.ExchangeCompletionListener;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.proxy.LoadBalancingProxyClient;
import io.undertow.server.handlers.proxy.ProxyConnection;
import io.undertow.server.handlers.proxy.ProxyHandler;
import io.undertow.util.AttachmentKey;
import io.undertow.util.AttachmentList;
import org.jboss.as.server.CurrentServiceContainer;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.evidence.PasswordGuessEvidence;

import java.lang.reflect.Field;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;

@SuppressWarnings("unchecked")
public class AuthFilter implements HttpHandler  {

    private final static Logger LOG = Logger.getLogger(AuthFilter.class.getName());

    private final IdentityManager identityManager;
    private final AuthenticationMechanism authenticationMechanism;
    private final HttpHandler next;

    private static AttachmentKey<AttachmentList<LoadBalancingProxyClient.Host>> ATTEMPTED_HOSTS;
    private static AttachmentKey<ProxyConnection> CONNECTION;

    public AuthFilter(HttpHandler next) {
        this.identityManager = new IdentityManagerImpl();
        this.authenticationMechanism = new BasicAuthenticationMechanism("proxy");
        this.next = new AuthenticationCallHandler(next);

        try {
            Field field = LoadBalancingProxyClient.class.getDeclaredField("ATTEMPTED_HOSTS");
            field.setAccessible(true);
            ATTEMPTED_HOSTS = (AttachmentKey<AttachmentList<LoadBalancingProxyClient.Host>>) field.get(null);

            field = ProxyHandler.class.getDeclaredField("CONNECTION");
            field.setAccessible(true);
            CONNECTION = (AttachmentKey<ProxyConnection>) field.get(null);

        } catch (Exception e) {
            //
        }
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        SecurityContext securityContext = new SecurityContextImpl(exchange, identityManager);
        securityContext.setAuthenticationRequired();
        securityContext.addAuthenticationMechanism(authenticationMechanism);
        exchange.setSecurityContext(securityContext);
        if(!exchange.isComplete()) {
            final long start = System.currentTimeMillis();
            exchange.addExchangeCompleteListener(new ExchangeCompletionListener() {
                @Override
                public void exchangeEvent(HttpServerExchange exchange, NextListener nextListener) {
                    StringBuilder sb = new StringBuilder("duration: ").append(System.currentTimeMillis() - start);
                    sb.append(";reql: ").append(exchange.getRequestContentLength());
                    sb.append(";respl: ").append(exchange.getResponseContentLength()).append(';');
                    exchange.getRequestHeaders().forEach(headerValue -> {
                        String name = headerValue.getHeaderName().toString();
                        if (!name.equalsIgnoreCase("Authorization")) {
                            sb.append(headerValue.getHeaderName()).append(": ").append(headerValue.getFirst()).append(" | ");
                        }
                    });
                    try {
                        sb.append(";attempted: ");
                        exchange.getAttachment(ATTEMPTED_HOSTS).forEach(host ->{
                            sb.append(host.getUri()).append(" | ");
                        });

                    } catch (Exception ignore) {
                        //
                    }
                    try {
                        ProxyConnection proxyConnection = exchange.getAttachment(CONNECTION);
                        if (proxyConnection != null) {
                            sb.append(";proxy: ").append(proxyConnection.getConnection().getPeerAddress())
                                    .append(proxyConnection.getTargetPath());
                        }
                    } catch (Exception ignore) {
                        //
                    }
                    LOG.severe(sb.toString());
                    nextListener.proceed();
                }
            });
        }
        next.handleRequest(exchange);
    }

    @SuppressWarnings("unchecked")
    private static class IdentityManagerImpl implements  IdentityManager {

        private final SecurityDomain securityDomain;

        private IdentityManagerImpl() {

            securityDomain = ((Service<SecurityDomain>) CurrentServiceContainer.getServiceContainer()
                    .getService(ServiceName.of("org", "wildfly", "security", "security-domain", "ProxyDomain"))
                    .getService())
                    .getValue();
        }

        @Override
        public Account verify(String id, Credential credential) {
            try {
                NamePrincipal principal = new NamePrincipal(id);
                PasswordGuessEvidence evidence = new PasswordGuessEvidence(((PasswordCredential) credential).getPassword());
                RealmIdentity realmIdentity = securityDomain.getIdentity(principal);
                if (realmIdentity.verifyEvidence(evidence)) {
                    return new Account() {

                        private static final long serialVersionUID = 1L;

                        @Override
                        public Principal getPrincipal() {
                            return principal;
                        }

                        @Override
                        public Set<String> getRoles() {
                            return Collections.emptySet();
                        }
                    };
                }
            } catch (Exception e) {
                // say nothing ...
            }
            return null;
        }

        @Override
        public Account verify(Account account) {
            return null;
        }

        @Override
        public Account verify(Credential credential) {
            return null;
        }
    }
}
