package org.example.proxy.server;

import com.sun.net.httpserver.*;
import science.mrcuijt.net.conn.SimpleURLConnection;
import science.mrcuijt.util.URLConnectionUtil;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class HttpServerDemo3 {

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8500), 0);
        HttpContext context = server.createContext("/");
        context.setHandler(HttpServerDemo3::handleRequest);
        server.start();
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        URI requestURI = exchange.getRequestURI();
        //printRequestInfo(exchange);
        String query = requestURI.getQuery();
        Content content = null;
        try {
            if (query != null && query.indexOf("url=") != -1) {
                System.out.println(query);
                String url = query.substring(query.indexOf("url=") + 4);
                content = get(getConnection(url));
                //FileUtil.write(content.getDatas(), String.format("Iserver_%d.dat",System.currentTimeMillis()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        OutputStream os = exchange.getResponseBody();
        if (content != null) {
            setResponseHeader(exchange, content.getHeaders());
            exchange.sendResponseHeaders(200, content.getDatas().length); // 0 chunked transfer
            URLConnectionUtil.readHeader(exchange.getResponseHeaders());
            os.write(content.getDatas());
        } else {
            String response = "This is the response at " + requestURI;
            exchange.getResponseHeaders().add("Demo", "demo");
            exchange.getResponseHeaders().put("Demo", Arrays.asList(new String[]{"demo"}));
            exchange.sendResponseHeaders(200, response.getBytes().length);
            //exchange.sendResponseHeaders(200, datas.length);
            os.write(response.getBytes());
            //os.write(datas);
        }
        os.close();
    }

    private static void setResponseHeader(HttpExchange exchange, Map<String, List<String>> headers) {
        Headers map = exchange.getResponseHeaders();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String key = entry.getKey();
            List<String> value = entry.getValue();
            if (key == null || key.equals("null")
                    || key.equalsIgnoreCase("Transfer-encoding") /* || key.equals("Content-Length")*/) continue;
            System.out.println(key);
            for (String v : value) {
                map.add(key, v);
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

    public static class Content {
        private Map<String, List<String>> headers;
        private byte[] datas = new byte[]{};

        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        public void setHeaders(Map<String, List<String>> headers) {
            this.headers = headers;
        }

        public byte[] getDatas() {
            return datas;
        }

        public void setDatas(byte[] datas) {
            this.datas = datas;
        }
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
}
