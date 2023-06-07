package org.example.proxy.server;

import com.sun.net.httpserver.*;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class HttpsServerDemo3 {

    final static String SERVER_PWD = "changeit";
    final static String KST_SERVER = "lig.keystore";
    final static String TST_SERVER = "lig.keystore";
    private static final int PORT = 9999;

    public static class MyHandler implements HttpHandler {

        // whether to use client cert authentication 
        private final boolean useClientCertAuth = true;
        private List<LdapName> allowedPrincipals = new ArrayList<LdapName>();
        private final boolean extendedClientCheck = true;
        private static final String CLIENTAUTH_OID = "1.3.6.1.5.5.7.3.2";


        @Override
        public void handle(HttpExchange t) throws IOException {
            String response = "Hallo Natalie!";
            HttpsExchange httpsExchange = (HttpsExchange) t;
            boolean auth;
            try {
                checkAuthentication(httpsExchange);
                auth = true;
            } catch (Exception ex) {
                response = ex.getMessage();
                auth = false;
            }
            boolean res = httpsExchange.getSSLSession().isValid();
            if (res) {
                String qry = httpsExchange.getRequestURI().getQuery();
                if (qry != null && qry.startsWith("qry=")) {
                    httpsExchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                    httpsExchange.sendResponseHeaders(200, response.length());
                    OutputStream os = t.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } else {
                    httpsExchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                    httpsExchange.sendResponseHeaders(200, response.length());
                    OutputStream os = t.getResponseBody();
                    os.write((response + " no query!").getBytes());
                    os.close();
                }
            }
        }

        // Verify https certs if its Https request and we have SSL auth enabled. Will be called before 
        // handling the request 
        protected void checkAuthentication(HttpExchange pHttpExchange) throws SecurityException {
            // Cast will always work since this handler is only used for Http 
            HttpsExchange httpsExchange = (HttpsExchange) pHttpExchange;
            if (useClientCertAuth) {
                checkCertForClientUsage(httpsExchange);
                checkCertForAllowedPrincipals(httpsExchange);
            }
        }

        // Check the cert's principal against the list of given allowedPrincipals. 
        // If no allowedPrincipals are given than every principal is allowed. 
        // If an empty list as allowedPrincipals is given, no one is allowed to access 
        private void checkCertForClientUsage(HttpsExchange pHttpsExchange) {
            try {
                String host = pHttpsExchange.getSSLSession().getPeerHost();
                //Principal p = pHttpsExchange.getSSLSession().getPeerPrincipal();
                String pr = pHttpsExchange.getSSLSession().getProtocol();
                Certificate[] peerCerts = pHttpsExchange.getSSLSession().getPeerCertificates();
                if (peerCerts != null && peerCerts.length > 0) {
                    X509Certificate clientCert = (X509Certificate) peerCerts[0];

                    // We required that the extended key usage must be present if we are using 
                    // client cert authentication 
                    if (extendedClientCheck &&
                            (clientCert.getExtendedKeyUsage() == null || !clientCert.getExtendedKeyUsage().contains(CLIENTAUTH_OID))) {
                        throw new SecurityException("No extended key usage available");
                    }
                }
            } catch (ClassCastException e) {
                throw new SecurityException("No X509 client certificate");
            } catch (CertificateParsingException e) {
                throw new SecurityException("Can't parse client cert");
            } catch (SSLPeerUnverifiedException e) {
                throw new SecurityException("SSL Peer couldn't be verified");
            }
        }

        private void checkCertForAllowedPrincipals(HttpsExchange pHttpsExchange) {
            if (allowedPrincipals != null) {
                X500Principal certPrincipal;
                try {
                    certPrincipal = (X500Principal) pHttpsExchange.getSSLSession().getPeerPrincipal();
                    Set<Rdn> certPrincipalRdns = getPrincipalRdns(certPrincipal);
                    for (LdapName principal : allowedPrincipals) {
                        for (Rdn rdn : principal.getRdns()) {
                            if (!certPrincipalRdns.contains(rdn)) {
                                throw new SecurityException("Principal " + certPrincipal + " not allowed");
                            }
                        }
                    }
                } catch (SSLPeerUnverifiedException e) {
                    throw new SecurityException("SSLPeer unverified");
                } catch (ClassCastException e) {
                    throw new SecurityException("Internal: Invalid Principal class provided " + e);
                }
            }
        }

        private Set<Rdn> getPrincipalRdns(X500Principal principal) {
            try {
                LdapName certAsLdapName = new LdapName(principal.getName());
                return new HashSet<Rdn>(certAsLdapName.getRdns());
            } catch (InvalidNameException e) {
                throw new SecurityException("Cannot parse '" + principal + "' as LDAP name");
            }
        }

    }


    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        try {
            // setup the socket address
            InetSocketAddress address = new InetSocketAddress(PORT);

            // initialise the HTTPS server
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // initialise the keystore
            // char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(KST_SERVER);// ("testkey.jks");
            ks.load(fis, SERVER_PWD.toCharArray());// password);

            // setup the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, SERVER_PWD.toCharArray());

            // setup the trust manager factory
            // TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            // tmf.init(ks);

            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(new FileInputStream(TST_SERVER), SERVER_PWD.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            // setup the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            SSLParameters sslp = sslContext.getSupportedSSLParameters();
            //sslp.setNeedClientAuth(true);
            sslp.setWantClientAuth(true);


            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                @Override
                public void configure(HttpsParameters params) {
                    try {
                        // initialise the SSL context
                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();
                        //params.setNeedClientAuth(true);
                        params.setWantClientAuth(true);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        // get the default parameters
                        SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                        SSLParameters sslParams = sslContext.getDefaultSSLParameters();
                        //sslParams.setNeedClientAuth(true);
                        sslParams.setWantClientAuth(true);

                        params.setSSLParameters(defaultSSLParameters);

                    } catch (Exception ex) {
                        System.out.println("Failed to create HTTPS port");
                    }
                }
            });
            httpsServer.createContext("/test", new MyHandler());
            httpsServer.setExecutor(
                    new ThreadPoolExecutor(4, 80, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(1000))); // creates
            // a
            // default
            // executor
            httpsServer.start();

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 62112 + " of localhost");
            exception.printStackTrace();

        }
    }

}