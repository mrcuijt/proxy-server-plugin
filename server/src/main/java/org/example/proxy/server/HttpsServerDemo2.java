package org.example.proxy.server;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyStore;

public class HttpsServerDemo2 {

    public static void main(String[] args) {

        int port = 8500;

        try {

            // Set up the socket address
            InetSocketAddress address = new InetSocketAddress(InetAddress.getLocalHost(), port);

            // Initialise the HTTPS server
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            HttpContext context = httpsServer.createContext("/");
            context.setHandler(HttpsServerDemo2::handleRequest);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Initialise the keystore
            char[] password = "changeit".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream("lig.keystore");
            ks.load(fis, password);

            // Set up the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            // Set up the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            // Set up the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        // Initialise the SSL context
                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        // Get the default parameters
                        SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                        params.setSSLParameters(defaultSSLParameters);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        System.out.println("Failed to create HTTPS port");
                    }
                }
            });
            httpsServer.start();
            //LigServer server = new LigServer(httpsServer);
            //joinableThreadList.add(server.getJoinableThread());
        } catch (Exception exception) {
            exception.printStackTrace();
            System.out.println("Failed to create HTTPS server on port " + port + " of localhost");
        }

    }


    private static void handleRequest(HttpExchange exchange) throws IOException {
        URI requestURI = exchange.getRequestURI();
        //printRequestInfo(exchange);
        String query = requestURI.getQuery();
        String response = "This is the response at " + requestURI;
        exchange.sendResponseHeaders(200, response.getBytes().length);
        //exchange.sendResponseHeaders(200, datas.length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        //os.write(datas);
        os.close();
    }
}