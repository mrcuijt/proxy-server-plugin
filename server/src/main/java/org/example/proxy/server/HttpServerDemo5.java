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

public class HttpServerDemo5 {

    private static final String privateKeyStr = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChfSOv8OFDWhM/cYuRlQ8nov+L9b4jfp7egQ5L3tn2rk0CbX1epNJAsE8HlFnoHnnI5T55mKazi3kSkBsJ9JoOutt30JWAGxO7CkoBJn55q2efqd284Y6gYqJiC3STKBhksQDobi3hxdymFcZvgLRWCam0yHE9OFl9qDePi6ciWOgHnOqY2xchC5zCqsEsv9HgKETNB0tNG9EMiEaz76UpdfBEM7xrAe93wiUHvT5vARJuuit1xxxH2dhxeZ4Fm4z3AsvudDynLp5FS5ob6sRGMj4Ny+gsxtMadcXxgcnk2E8BqtSqE5w2NfLz+hSIuRqmCoUmQeHSzoz3WFGj/OINAgMBAAECggEAFQGfO8q8srMr38vYWOan4wML9NvRkPJungjxoCLr/W+s6sztSvtrsih9D0JX857LPru7Rbv6q05QQH7oVYIw7AuYctx6JgDfryvmdoHYX+FRCG7jPielEu3hq5lL37yOd8KimJmEdGL1kdExT93RF4QIRFDykgEbewH/wDdtVUVAGeoYn+nwA1JDIAHCdKTdPU2Z7VWM0SMpB0ujoRThn6xIbaGTlY2X1RQKVjTN21FRxl4PUfXsORgeJHVlHlr+JM9rYfW4tA5rTY8CaG66XQmRNI3OVOPx7tfVQKGuf7a7TNG6Ug2BHcB4DLLDi+DFqQBV7j6NpzQr9ev5oX07IQKBgQDlR0Y8MJ6JSYrR7dvimmLjKkuEOY5dldOKOKg5mBkrs4o2VglWAsEezvo+PszMOvgDzAqF7Wqu0DVNXWCmYti2cerUY3wTXMPVeHwblI+TYpuN9ymvZtxuUDtwsWYdclyq00R0TbfnRLsk02xY1elPQAvKEZ91RfA0hU6E5V03hQKBgQC0T01i0rQiDwyQvxmwSM/EomDIxqh14Nf2RnoiSa1fh1cyvasKCHv9xfFzGsPSFU9iEP0htAviKSp3ismNbfdYIePM3BsBY22JSec/mqGGmYnT+EYQsW1jDfsmABZqIW1JcjSNti5jMh2CkX/h4GL7bA+jq5t9hi1gs2JPRKYS6QKBgGmwOz4Po2Thk65FmPCR/jd9DaZ76ZZWNFco2tMBu8ibUIDPlCojxuXuvwfmZv1VyXHmoost79l5fLiW7LCGLCOdy4PwAAfk4RkMGxmTl8N21wHQB1Ulc0MelOfTvqCgUPslvA5orPdchW/qTa19nbi8azLQgNLMVHfBY3p7SEcJAoGAQjhhvmqN13hZcAuPHqwPCjNsgjBbjDdQeVU248LVVqE5CByaZWvqRbBd1Z09z7kd13FP1gHu31epDhA9p6B8V7TSmdk4XdErWGF4+WYL7ogTE3M6IEVZXCi1VSZxFPdD0NaNsIH5FVtBdUOEiOtEzvvH3p9W0snlfn9DGsOmjokCgYASHJUH7GmnawqHMNvuQcRxFsQjfrKTwRUQCUCqw0yxQakuEQrcoYe2pMzomkpniVHp7y5HGJ4rRA0DLzCsS5ZTzzZ0hvDdpR0uE+OiShgYI9DNK/USo5CehcKiJiW/w2MqLC3bzQC/ZbeY08NuCi5ohBrbhbjEBP5An5TjqNtaBg==";

    private static final String publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoX0jr/DhQ1oTP3GLkZUPJ6L/i/W+I36e3oEOS97Z9q5NAm19XqTSQLBPB5RZ6B55yOU+eZims4t5EpAbCfSaDrrbd9CVgBsTuwpKASZ+eatnn6ndvOGOoGKiYgt0kygYZLEA6G4t4cXcphXGb4C0VgmptMhxPThZfag3j4unIljoB5zqmNsXIQucwqrBLL/R4ChEzQdLTRvRDIhGs++lKXXwRDO8awHvd8IlB70+bwESbrordcccR9nYcXmeBZuM9wLL7nQ8py6eRUuaG+rERjI+DcvoLMbTGnXF8YHJ5NhPAarUqhOcNjXy8/oUiLkapgqFJkHh0s6M91hRo/ziDQIDAQAB";

    private static RSACrypt crypt = new RSACrypt(privateKeyStr, publicKeyStr);

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(12791), 0);
        HttpContext context = server.createContext("/");
        context.setHandler(HttpServerDemo5::handleRequest);
        server.start();
    }

    // 1. POST Request
    // 2. Request Body i=encrypt
    private static void handleRequest(HttpExchange exchange) throws IOException {

        URI requestURI = exchange.getRequestURI();

        System.out.println("=========Request Header=========");
        URLConnectionUtil.readHeader(exchange.getRequestHeaders());
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
            Content content = loop(getConnection(url));
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
