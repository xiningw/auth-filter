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
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import org.jboss.as.server.CurrentServiceContainer;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.evidence.PasswordGuessEvidence;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

public class AuthFilter implements HttpHandler  {

    private final IdentityManager identityManager;
    private final AuthenticationMechanism authenticationMechanism;
    private final HttpHandler next;

    public AuthFilter(HttpHandler next) {
        this.identityManager = new IdentityManagerImpl();
        this.authenticationMechanism = new BasicAuthenticationMechanism("proxy");
        this.next = new AuthenticationCallHandler(next);
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        SecurityContext securityContext = new SecurityContextImpl(exchange, identityManager);
        securityContext.setAuthenticationRequired();
        securityContext.addAuthenticationMechanism(authenticationMechanism);
        exchange.setSecurityContext(securityContext);
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
