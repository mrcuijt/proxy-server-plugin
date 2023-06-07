package org.example.proxy.client;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.example.proxy.util.AESCryptUtil;
import org.example.proxy.util.RSACryptUtil;
import science.mrcuijt.net.conn.SimpleURLConnection;
import science.mrcuijt.util.URLConnectionUtil;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;


public class ClientDemo4 {
    static String NO_KEYSTORE = "";
    static String UNAUTH_KEYSTORE = "keys/unauthclient.jks"; // Doesn't exist in server trust store, should fail authentication.
    static String AUTH_KEYSTORE = "keys/authclient.jks"; // Exists in server trust store, should pass authentication.
    static String TRUSTSTORE = "keys/clienttrust.jks";
    static String CLIENT_PWD = "aaaaaa";

    public static ThreadPoolExecutor getExecutor() {
        return new ThreadPoolExecutor(
                10,
                15,
                2,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(10000));
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8500), 0);
        server.setExecutor(getExecutor());
        HttpContext context = server.createContext("/");
        context.setHandler(ClientDemo4::handleRequest);
        server.start();

//        ClientDemo4 cl = new ClientDemo4();
//        System.out.println("No keystore:");
//        cl.testIt(NO_KEYSTORE);
//        System.out.println("Unauth keystore:");
//        cl.testIt(UNAUTH_KEYSTORE);
//        System.out.println("Auth keystore:");
//        cl.testIt(AUTH_KEYSTORE);
//        System.out.println("Trust keystore:");
//        cl.testIt(TRUSTSTORE);
    }


    public void testIt(String jksFile) {
        try {
            //String https_url = "https://localhost:8888/auth/";
            String https_url = "https://localhost:8888/auth/";
            URL url;
            url = new URL(https_url);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(getSSLFactory(jksFile));

            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setUseCaches(false);

            // Print response
            BufferedReader bir = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line = null;
            while ((line = bir.readLine()) != null) {
                System.out.println(line);
            }
            bir.close();
            conn.disconnect();
        } catch (SSLHandshakeException | SocketException e) {
            System.out.println(e.getMessage());
            System.out.println("");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SSLSocketFactory getSSLFactory(String jksFile) throws Exception {
        // Create key store
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyManager[] kmfs = null;
        if (jksFile.length() > 0) {
            keyStore.load(new FileInputStream(jksFile), CLIENT_PWD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, CLIENT_PWD.toCharArray());
            kmfs = kmf.getKeyManagers();
        }

        // create trust store (validates the self-signed server!)
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(new FileInputStream(TRUSTSTORE), CLIENT_PWD.toCharArray());
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmfs, trustFactory.getTrustManagers(), null);
        return sslContext.getSocketFactory();
    }


    // 1. 请求路径带有 querystring url 参数
    // 2. url 参数符合 http/https 路径
    // 3. url 参数 + currentTimeMillis() RSA Encrypt , 加密后以 POST 请求转发给后端服务器。
    // 4. 获取后端服务器返回数据，RSA Decrypt 返回

    // 不符合条件，返回 querystring

    private static void handleRequest(HttpExchange exchange) throws IOException {
        URI requestURI = exchange.getRequestURI();
        //printRequestInfo(exchange);
        String query = requestURI.getQuery();

        boolean verifyResult = true;

        String dispatcher = null;
        if (query == null || query.length() < 7 || query.indexOf("url=") == -1) {
            verifyResult = false;
        } else {
            dispatcher = query.substring(query.indexOf("url=") + 4);
        }

        if (verifyResult) {
            if (!dispatcher.startsWith("http://") && !dispatcher.startsWith("https://")) {
                verifyResult = false;
            }
        }

        OutputStream os = exchange.getResponseBody();

        if (!verifyResult) { // Response querystring
            if (query == null) query = "/";
            byte[] response = query.getBytes();
            exchange.sendResponseHeaders(200, response.length);
            os.write(response);
            os.close();
            return;
        }

        // Dispatcher Request
        //String proxyserver = "http://127.0.0.1:12791/";
        String proxyserver = "https://127.0.0.1:8888/";
        Content content = null;
        String password = System.currentTimeMillis() + "";
        String encrypt = RSACryptUtil.bencode(AESCryptUtil.encrypt((dispatcher + password).getBytes(), password + "123"));
        String payload = "i=" + encrypt + password;
        Map<String, List<String>> requestHeader = exchange.getRequestHeaders();
        System.out.println("=========Request Header=========");
        //URLConnectionUtil.readHeader(exchange.getResponseHeaders());
        URLConnectionUtil.readHeader(requestHeader);
        requestHeader.put(CONTENT_LENGTH, Arrays.asList(new String[]{payload.getBytes().length + ""}));
        // Proxy Server Response, [Reuest Header , Payload]
        content = loop(proxyserver, "POST", requestHeader, payload);
        try {
            password += "123";
            byte[] decrypt = AESCryptUtil.decrypt(content.getDatas(), password);
            //byte[] decrypt = crypt.decrypt(content.getDatas());
            if (decrypt == null) {
                if (query == null) query = "/";
                byte[] response = query.getBytes();
                exchange.sendResponseHeaders(200, response.length);
                os.write(response);
                os.close();
                return;
            }


            byte[] datas = new byte[decrypt.length - 13];
            System.out.println(decrypt.length);
            System.out.println(datas.length);
            System.arraycopy(decrypt, 13, datas, 0, datas.length);

            if (datas.length == 0) {
                URLConnectionUtil.readHeader(content.getHeaders());
                setResponseHeader(exchange, content.getHeaders());
                exchange.sendResponseHeaders(200, datas.length);
                os.flush();
                os.close();
                return;
            }

            // Set Response Header
            content.getHeaders().put(CONTENT_LENGTH, Arrays.asList(new String[]{decrypt.length - 13 + ""}));
            setResponseHeader(exchange, content.getHeaders());
            System.out.println("=========Response Header=========");
            //URLConnectionUtil.readHeader(exchange.getResponseHeaders());
            URLConnectionUtil.readHeader(content.getHeaders());
            // 200 OK, Content-Length
            exchange.sendResponseHeaders(200, decrypt.length - 13);
            //FileUtil.write(datas, "data_" + password);
            //os.write(decrypt, 13, decrypt.length); // has error verify decrypt.length == decrypt.length - 13
            ByteArrayInputStream bais = new ByteArrayInputStream(datas);
            int iRead = -1;
            byte[] buffer = new byte[1024];
            while ((iRead = bais.read(buffer, 0, buffer.length)) != -1) {
                os.write(buffer, 0, iRead);
            }
            //os.write(datas);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            os.flush();
            os.close();
        }
    }

    private static void setResponseHeader(HttpExchange exchange, Map<String, List<String>> headers) {
        if (headers == null || headers.keySet().size() == 0) return;
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
        private Map<String, List<String>> headers;
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

    public static Content loop(String proxyserver, String method, Map<String, List<String>> requestHeader, String payload) {
        Content content = new Content();
        boolean status = false;
        int count = 0;
        while (!status) {
            count++;
            try {
                content = get(getConnection(proxyserver, "POST", requestHeader), payload);
                status = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (count >= 2) break;
        }
        return content;
    }

    static final String CONTENT_LENGTH = "Content-Length";

    public static Content get(HttpURLConnection conn, String payload) throws Exception {
        Content content = new Content();
        InputStream is = null;
        try {

            // Set Payload
            OutputStream os = conn.getOutputStream();
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(os));
            pw.write(payload);
            pw.close();

            Map<String, List<String>> headers = conn.getHeaderFields();
            URLConnectionUtil.readHeader(headers);
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
            //int code = conn.getResponseCode();
            //String codeMessage = conn.getResponseMessage();
            //System.out.println(String.format("Response Code : %d ; Response Message : %s ;", code, codeMessage));
            //if(code >= 400 && code <= 499) return content;
            //if(code >= 500 && code <= 599) return content;
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
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
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
        return content;
    }

    public static HttpURLConnection getConnection(String url) {
        return getConnection(url, "GET", null);
    }

    public static HttpURLConnection getConnection(String url, String method) {
        return getConnection(url, method, null);
    }

    public static HttpURLConnection getConnection(String url, String method, Map<String, List<String>> headers) {
        HttpURLConnection conn = null;
        try {
            conn = SimpleURLConnection.getInstance().getConnection(url, method);
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSSLFactory(AUTH_KEYSTORE));
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
}