package org.example.proxy.server;

import com.sun.net.httpserver.*;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.example.proxy.util.AESCryptUtil;
import org.example.proxy.util.RSACryptUtil;
import science.mrcuijt.net.conn.SimpleURLConnection;
import science.mrcuijt.util.URLConnectionUtil;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class HttpsServerDemo5 {

    final static String SERVER_PWD = "aaaaaa";
    final static String KST_SERVER = "keys/server.jks";
    final static String TST_SERVER = "keys/servertrust.jks";

    final static TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[]{};
                }
            }
    };

    final static HostnameVerifier verifiedAllHostname = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    public static SSLSocketFactory sslSocketFactory = getSSLSocketFactory(trustAllCerts);

    public static HttpsServer server;

    public static ThreadPoolExecutor getExecutor() {
        return new ThreadPoolExecutor(
                10,
                15,
                2,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(10000));
    }

    public static void main(String[] args) throws Exception {
        server = makeServer();
        server.start();

        //System.out.println("Server running, hit enter to stop.\n"); System.in.read();
        //AuthClient cl = new AuthClient(); cl.testIt(); 
        //server.stop(0);
    }

    public static HttpsServer makeServer() throws Exception {
        server = HttpsServer.create(new InetSocketAddress(8888), 0);
        server.setExecutor(getExecutor());
        //server.setHttpsConfigurator(new HttpsConfigurator(SSLContext.getInstance("TLS"))); // Default config with no auth requirement.
        SSLContext sslCon = createSSLContext();
        MyConfigger authconf = new MyConfigger(sslCon);
        server.setHttpsConfigurator(authconf);

        server.createContext("/", HttpsServerDemo5::handleRequest);
        //server.createContext("/auth", new HelloHandler());
        return server;
    }

    private static SSLContext createSSLContext() {
        SSLContext sslContext = null;
        KeyStore ks;
        KeyStore ts;

        try {
            sslContext = SSLContext.getInstance("TLS");

            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KST_SERVER), SERVER_PWD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, SERVER_PWD.toCharArray());

            ts = KeyStore.getInstance("JKS");
            ts.load(new FileInputStream(TST_SERVER), SERVER_PWD.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return sslContext;
    }

    // 1. POST Request
    // 2. Request Body i=encrypt
    private static void handleRequest(HttpExchange exchange) throws IOException {

        URI requestURI = exchange.getRequestURI();

        System.out.println("=========Request Header=========");
        URLConnectionUtil.readHeader(exchange.getRequestHeaders());
//        exchange.sendResponseHeaders(200, 0);
//        OutputStream os1 = exchange.getResponseBody();
//        os1.flush();
//        os1.close();
//        if (true) return;
        int length = 0;
        List<String> list = exchange.getRequestHeaders().get(CONTENT_LENGTH);
        if (list != null && list.size() > 0) {
            try {
                length = Integer.parseInt(list.get(0));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = exchange.getRequestBody();
        String url = null;
        int len = -1;
        int read = 0;
        byte[] buffer = new byte[1024];
        if (length != 0) {
            while (read != length && length - read > 0 && (len = is.read(buffer, 0, length - read)) != -1) {
                baos.write(buffer, 0, len);
            }
            String content = new String(baos.toByteArray());
            if (content.indexOf("&") != -1) {
                String[] params = content.split("&");
                for (String param : params) {
                    if (param.startsWith("i=")) {
                        String paramValue = param.substring(2, param.length() - 13);
                        String password = param.substring(param.length() - 13) + "123";
                        //System.out.println("================paramValue:" + paramValue);
                        //URLDecoder decode = new URLDecoder();
                        //String encrypt = decode.decode(paramValue);
                        System.out.println("================encrypt:" + paramValue);
                        byte[] decrypt = AESCryptUtil.decrypt(RSACryptUtil.bdecode(paramValue), password);
                        //byte[] decrypt = crypt.decrypt(paramValue);
                        url = new String(decrypt);
                        System.out.println("================decrypt:" + url);
                        break;
                    }
                }
            } else {
                if (content.startsWith("i=")) {
                    String paramValue = content.substring(2, content.length() - 13);
                    String password = content.substring(content.length() - 13) + "123";
                    //System.out.println("================paramValue:" + paramValue);
                    //URLDecoder decode = new URLDecoder();
                    //String encrypt = decode.decode(paramValue);
                    System.out.println("================encrypt:" + paramValue);
                    byte[] decrypt = AESCryptUtil.decrypt(RSACryptUtil.bdecode(paramValue), password);
                    //byte[] decrypt = crypt.decrypt(paramValue);
                    url = new String(decrypt);
                    System.out.println("================decrypt:" + url);
                }
            }
        }

        OutputStream os = exchange.getResponseBody();
        String password = null;
        if (url != null) {
            password = url.substring(url.length() - 13) + "123";
            url = url.substring(0, url.length() - 13);
            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            Content content = null;
            if (url.indexOf(".hanime.tv/api") != -1
                    || url.indexOf(".hanime.tv/rapi") != -1)
                content = loop(buildOkHttp(url, exchange.getRequestHeaders()));
            else content = loop(getConnection(url));
            baos2.write((System.currentTimeMillis() + "").getBytes());
            baos2.write(content.getDatas());
            System.out.println("Encrypt Data");
            byte[] datas = AESCryptUtil.encrypt(baos2.toByteArray(), password);
            //String encrypt = crypt.encrypt(baos2.toByteArray());
            System.out.println("Encrypt Data Finished.");
            //byte[] datas = encrypt.getBytes();
            content.getHeaders().put(CONTENT_LENGTH, Arrays.asList(new String[]{datas.length + ""}));
            System.out.println("=========Response Header=========");
            URLConnectionUtil.readHeader(content.getHeaders());
            setResponseHeader(exchange, content.getHeaders());
            exchange.sendResponseHeaders(200, datas.length);
            System.out.println("write response");
            os.write(datas);
            os.flush();
            os.close();
        } else {
            exchange.sendResponseHeaders(500, 0);
            os.close();
        }
    }

    private static void setResponseHeader(HttpExchange exchange, Map<String, List<String>> headers) {
        Headers map = exchange.getResponseHeaders();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String key = entry.getKey();
            List<String> value = entry.getValue();
            if (key == null || key.equals("null")
                    || key.equalsIgnoreCase("Transfer-encoding") /* || key.equals("Content-Length")*/) continue;
            for (String v : value) {
                map.add(key, v);
            }
        }
    }


    public static class Content {
        private Map<String, List<String>> headers = new HashMap<String, List<String>>();
        private byte[] datas = new byte[]{};

        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        public void setHeaders(Map<String, List<String>> headers) {
            if (headers == null || headers.keySet().size() == 0) return;
            this.headers = new HashMap<String, List<String>>();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                String key = entry.getKey();
                List<String> value = entry.getValue();
                if (key == null || key.equals("null")
                        || key.equalsIgnoreCase("Transfer-encoding")
                        || key.equalsIgnoreCase("Content-Length")) continue;
                this.headers.put(key, value);
            }
        }

        public byte[] getDatas() {
            return datas;
        }

        public void setDatas(byte[] datas) {
            this.datas = datas;
        }
    }

    public static Content loop(HttpURLConnection conn) {
        Content content = new Content();
        boolean status = false;
        int count = 0;
        while (!status) {
            count++;
            try {
                content = get(conn);
                status = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (count >= 2) break;
        }
        return content;
    }

    static final String CONTENT_LENGTH = "Content-Length";

    public static Content get(HttpURLConnection conn) {
        Content content = new Content();
        InputStream is = null;
        try {
            Map<String, List<String>> headers = conn.getHeaderFields();
            content.setHeaders(headers);
            long length = 0;
            List<String> list = headers.get(CONTENT_LENGTH);
            if (list != null && list.size() > 0) {
                try {
                    length = Long.valueOf(list.get(0));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            int code = conn.getResponseCode();
            String codeMessage = conn.getResponseMessage();
            System.out.println(String.format("Response Code : %d ; Response Message : %s ;", code, codeMessage));
            if (code >= 400 && code <= 499) return content;
            if (code >= 500 && code <= 599) return content;
            System.out.println();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            is = conn.getInputStream();
            // buffer
            byte[] buffer = new byte[1024];
            int len = 0;
            while ((len = is.read(buffer, 0, buffer.length)) != -1) {
                out.write(buffer, 0, len);
            }
            byte[] datas = out.toByteArray();
            if (length != 0) {
                System.out.println(String.format("Content-Length : %d ; Read Length : %d ;", length, datas.length));
                if (length != datas.length) throw new RuntimeException("EOF read");
            }
            content.setDatas(datas);
            System.out.println("Downloader Finished.");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (is != null) is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (conn != null) {
                    conn.disconnect();
                    conn = null;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("Return Content.");
        return content;
    }

    public static SSLSocketFactory getSSLSocketFactory(TrustManager[] trustAllCerts) {
        SSLSocketFactory sslSocketFactory = null;
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sslSocketFactory;
    }

    public static OkHttpClient client = new OkHttpClient.Builder()
            .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
            .hostnameVerifier(verifiedAllHostname)
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build();

    // ok http
    public static Request buildOkHttp(String url, Map<String, List<String>> headers) {
        Request.Builder builder = new Request.Builder();
        builder.url(url);
        if (headers != null && headers.keySet().size() > 0) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                String key = entry.getKey();
                List<String> values = entry.getValue();
                if (key == null || key.equals("null")
                        || key.equalsIgnoreCase("Host")
                        || key.equalsIgnoreCase("Scheme")
                        || key.equalsIgnoreCase("Authority")
                        || key.equalsIgnoreCase("Path")
                        || key.equalsIgnoreCase("Method")
                        || key.equalsIgnoreCase("Transfer-encoding")
                        || key.equalsIgnoreCase("Content-type")
                        || key.equalsIgnoreCase("Content-Length")) continue;
                if (values == null || values.size() == 0) {
                    builder.addHeader(key, "");
                } else {
                    builder.addHeader(key, values.get(0));
                }
            }
        }

        Request request = builder.build();
        return request;
    }

    public static Map<String, List<String>> okHttpHeader(Response response) {
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        okhttp3.Headers responseHeaders = response.headers();
        int responseHeadersLength = responseHeaders.size();
        for (int i = 0; i < responseHeadersLength; i++) {
            String headerName = responseHeaders.name(i);
            String headerValue = responseHeaders.get(headerName);
            if (headerValue == null) headerValue = "";
            headers.put(headerName, Arrays.asList(new String[]{headerValue}));
        }
        return headers;
    }

    public static Content get(Request request) {
        Content content = new Content();
        InputStream is = null;
        Response response = null;
        try {
            response = client.newCall(request).execute();
            if (!response.isSuccessful()) throw new RuntimeException("Unexpected code " + response);
            Map<String, List<String>> headers = okHttpHeader(response);
            content.setHeaders(headers);
            long length = 0;
            List<String> list = headers.get(CONTENT_LENGTH);
            if (list != null && list.size() > 0) {
                try {
                    length = Long.valueOf(list.get(0));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            is = response.body().byteStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // buffer
            byte[] buffer = new byte[1024];
            int len = -1;
            while ((len = is.read(buffer, 0, buffer.length)) != -1) {
                out.write(buffer, 0, len);
            }
            byte[] datas = out.toByteArray();
            if (length != 0) {
                System.out.println(String.format("Content-Length : %d ; Read Length : %d ;", length, datas.length));
                if (length != datas.length) throw new RuntimeException("EOF read");
            }
            content.setDatas(datas);
            System.out.println("Downloader Finished.");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (is != null) is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (response != null) response.body().close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("Return Content.");
        return content;
    }

    public static Content loop(Request request) {
        Content content = new Content();
        boolean status = false;
        int count = 0;
        while (!status) {
            count++;
            try {
                content = get(request);
                status = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (count >= 2) break;
        }
        return content;
    }

    public static HttpURLConnection getConnection(String url) {
        return getConnection(url, null);
    }

    public static HttpURLConnection getConnection(String url, Map<String, List<String>> headers) {
        HttpURLConnection conn = null;
        try {
            conn = SimpleURLConnection.getInstance().getConnection(url);
            setRequestHeader(conn, headers);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return conn;
    }

    public static void setRequestHeader(HttpURLConnection conn, Map<String, List<String>> headers) {
        if (headers != null && headers.entrySet().size() > 0) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                String header = entry.getKey();
                List<String> values = entry.getValue();
                if (values == null || values.size() == 0) continue;
                conn.setRequestProperty(header, values.get(0));
            }
        }
    }


    public static class MyConfigger extends HttpsConfigurator {
        public MyConfigger(SSLContext sslContext) {
            super(sslContext);
        }

        @Override
        public void configure(HttpsParameters params) {
            SSLContext sslContext = getSSLContext();
            SSLParameters sslParams = sslContext.getDefaultSSLParameters();
            sslParams.setNeedClientAuth(true);
            params.setNeedClientAuth(true);
            params.setSSLParameters(sslParams);
        }
    }

    public static class HelloHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            HttpsExchange ts = (HttpsExchange) t;
            SSLSession sess = ts.getSSLSession();
            //if( sess.getPeerPrincipal() != null) System.out.println(sess.getPeerPrincipal().toString()); // Principal never populated.
            System.out.printf("Responding to host: %s\n", sess.getPeerHost());

            t.getResponseHeaders().set("Content-Type", "text/plain");
            t.sendResponseHeaders(200, 0);
            String response = "Hello!  You seem trustworthy!\n";
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}