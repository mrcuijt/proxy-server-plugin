package org.example.proxy.server;

import com.sun.net.httpserver.*;
import org.example.proxy.util.AESCryptUtil;
import org.example.proxy.util.RSACrypt;
import org.example.proxy.util.RSACryptUtil;
import science.mrcuijt.net.conn.SimpleURLConnection;
import science.mrcuijt.util.URLConnectionUtil;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpServerDemo4 {

    private static final String privateKeyStr = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChfSOv8OFDWhM/cYuRlQ8nov+L9b4jfp7egQ5L3tn2rk0CbX1epNJAsE8HlFnoHnnI5T55mKazi3kSkBsJ9JoOutt30JWAGxO7CkoBJn55q2efqd284Y6gYqJiC3STKBhksQDobi3hxdymFcZvgLRWCam0yHE9OFl9qDePi6ciWOgHnOqY2xchC5zCqsEsv9HgKETNB0tNG9EMiEaz76UpdfBEM7xrAe93wiUHvT5vARJuuit1xxxH2dhxeZ4Fm4z3AsvudDynLp5FS5ob6sRGMj4Ny+gsxtMadcXxgcnk2E8BqtSqE5w2NfLz+hSIuRqmCoUmQeHSzoz3WFGj/OINAgMBAAECggEAFQGfO8q8srMr38vYWOan4wML9NvRkPJungjxoCLr/W+s6sztSvtrsih9D0JX857LPru7Rbv6q05QQH7oVYIw7AuYctx6JgDfryvmdoHYX+FRCG7jPielEu3hq5lL37yOd8KimJmEdGL1kdExT93RF4QIRFDykgEbewH/wDdtVUVAGeoYn+nwA1JDIAHCdKTdPU2Z7VWM0SMpB0ujoRThn6xIbaGTlY2X1RQKVjTN21FRxl4PUfXsORgeJHVlHlr+JM9rYfW4tA5rTY8CaG66XQmRNI3OVOPx7tfVQKGuf7a7TNG6Ug2BHcB4DLLDi+DFqQBV7j6NpzQr9ev5oX07IQKBgQDlR0Y8MJ6JSYrR7dvimmLjKkuEOY5dldOKOKg5mBkrs4o2VglWAsEezvo+PszMOvgDzAqF7Wqu0DVNXWCmYti2cerUY3wTXMPVeHwblI+TYpuN9ymvZtxuUDtwsWYdclyq00R0TbfnRLsk02xY1elPQAvKEZ91RfA0hU6E5V03hQKBgQC0T01i0rQiDwyQvxmwSM/EomDIxqh14Nf2RnoiSa1fh1cyvasKCHv9xfFzGsPSFU9iEP0htAviKSp3ismNbfdYIePM3BsBY22JSec/mqGGmYnT+EYQsW1jDfsmABZqIW1JcjSNti5jMh2CkX/h4GL7bA+jq5t9hi1gs2JPRKYS6QKBgGmwOz4Po2Thk65FmPCR/jd9DaZ76ZZWNFco2tMBu8ibUIDPlCojxuXuvwfmZv1VyXHmoost79l5fLiW7LCGLCOdy4PwAAfk4RkMGxmTl8N21wHQB1Ulc0MelOfTvqCgUPslvA5orPdchW/qTa19nbi8azLQgNLMVHfBY3p7SEcJAoGAQjhhvmqN13hZcAuPHqwPCjNsgjBbjDdQeVU248LVVqE5CByaZWvqRbBd1Z09z7kd13FP1gHu31epDhA9p6B8V7TSmdk4XdErWGF4+WYL7ogTE3M6IEVZXCi1VSZxFPdD0NaNsIH5FVtBdUOEiOtEzvvH3p9W0snlfn9DGsOmjokCgYASHJUH7GmnawqHMNvuQcRxFsQjfrKTwRUQCUCqw0yxQakuEQrcoYe2pMzomkpniVHp7y5HGJ4rRA0DLzCsS5ZTzzZ0hvDdpR0uE+OiShgYI9DNK/USo5CehcKiJiW/w2MqLC3bzQC/ZbeY08NuCi5ohBrbhbjEBP5An5TjqNtaBg==";

    private static final String publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoX0jr/DhQ1oTP3GLkZUPJ6L/i/W+I36e3oEOS97Z9q5NAm19XqTSQLBPB5RZ6B55yOU+eZims4t5EpAbCfSaDrrbd9CVgBsTuwpKASZ+eatnn6ndvOGOoGKiYgt0kygYZLEA6G4t4cXcphXGb4C0VgmptMhxPThZfag3j4unIljoB5zqmNsXIQucwqrBLL/R4ChEzQdLTRvRDIhGs++lKXXwRDO8awHvd8IlB70+bwESbrordcccR9nYcXmeBZuM9wLL7nQ8py6eRUuaG+rERjI+DcvoLMbTGnXF8YHJ5NhPAarUqhOcNjXy8/oUiLkapgqFJkHh0s6M91hRo/ziDQIDAQAB";

    private static RSACrypt crypt = new RSACrypt(privateKeyStr, publicKeyStr);

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8500), 0);
        HttpContext context = server.createContext("/");
        context.setHandler(HttpServerDemo4::handleRequest);
        server.start();
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
        String proxyserver = "http://127.0.0.1:12791/";
        Content content = null;
        String password = System.currentTimeMillis() + "";
        String encrypt = RSACryptUtil.bencode(AESCryptUtil.encrypt((dispatcher + password).getBytes(), password + "123"));
        String payload = "i=" + encrypt + password;
        Map<String, List<String>> requestHeader = exchange.getRequestHeaders();
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


    private static void printRequestInfo(HttpExchange exchange) {
        System.out.println("-- Client Info --");
        //InetSocketAddress remoteAddress = exchange.getRemoteAddress();
        //String remoteHost = remoteAddress.getHostName();
        //System.out.println(String.format("RemoteAddress:%s; RemoteHost:%s;", remoteAddress, remoteHost));

        System.out.println("-- headers --");
        Headers requestHeaders = exchange.getRequestHeaders();
        requestHeaders.entrySet().forEach(System.out::println);

        System.out.println("-- principle --");
        HttpPrincipal principal = exchange.getPrincipal();
        System.out.println(principal);

        System.out.println("-- HTTP method --");
        String requestMethod = exchange.getRequestMethod();
        System.out.println(requestMethod);

        System.out.println("-- query --");
        URI requestURI = exchange.getRequestURI();
        String query = requestURI.getQuery();
        System.out.println(query);
        System.out.println("-- request body --");
        FileOutputStream fos = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            InputStream is = exchange.getRequestBody();
            byte[] buffer = new byte[1024];
            int length = 0;
            while ((length = is.read(buffer, 0, buffer.length)) != -1) {
                baos.write(buffer, 0, length);
            }
            fos = new FileOutputStream(new File(String.format("server_%d.dat", System.currentTimeMillis())));
            fos.write(baos.toByteArray());
            fos.flush();
            System.out.println(new String(baos.toByteArray(), "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) fos.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
