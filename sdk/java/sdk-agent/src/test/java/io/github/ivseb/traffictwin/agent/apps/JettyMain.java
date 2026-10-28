package io.github.ivseb.traffictwin.agent.apps;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

final class JettyMain {
    private JettyMain() {}

    static void start() throws Exception {
        Server server = new Server();
        ServerConnector c = new ServerConnector(server);
        c.setHost("127.0.0.1");
        server.addConnector(c);
        ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
        ctx.setContextPath("/");
        ctx.addServlet(new ServletHolder(new JakartaOrdersServlet()), "/*");
        server.setHandler(ctx);
        server.start();
        System.out.println("PORT=" + c.getLocalPort());
        System.out.flush();
        server.join();
    }
}
