package io.github.ivseb.traffictwin.agent.apps;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JavaxOrdersServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String qs = req.getQueryString();
        // "read=partial": like a JSON parser (Jackson under @RequestBody), stop at the closing brace and never read the end of the stream.
        byte[] in = qs != null && qs.contains("read=partial") ? Shop.readJsonObject(req.getInputStream()) : req.getInputStream().readAllBytes();
        String out;
        try {
            out = Shop.order(in);
        } catch (Exception e) {
            res.sendError(500, String.valueOf(e));
            return;
        }
        res.setStatus(201);
        res.setContentType("application/json; charset=utf-8");
        res.getOutputStream().write(out.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        res.setContentType("text/plain");
        res.getWriter().write("ok");
    }
}
