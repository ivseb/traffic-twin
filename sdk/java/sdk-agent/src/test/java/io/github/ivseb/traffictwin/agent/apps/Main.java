package io.github.ivseb.traffictwin.agent.apps;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * An embedded servlet container started the way an ordinary application does it: no traffic-twin
 * import, no filter. {@code Main tomcat|tomcat9|jetty}. Prints {@code PORT=<n>} when it listens.
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "tomcat" -> tomcat("io.github.ivseb.traffictwin.agent.apps.JakartaOrdersServlet");
            case "tomcat9" -> tomcat("io.github.ivseb.traffictwin.agent.apps.JavaxOrdersServlet");
            case "jetty" -> JettyMain.start();
            default -> throw new IllegalArgumentException(args[0]);
        }
    }

    private static void tomcat(String servletClass) throws Exception {
        Path base = Files.createTempDirectory("tt-tomcat");
        org.apache.catalina.startup.Tomcat t = new org.apache.catalina.startup.Tomcat();
        t.setBaseDir(base.toString());
        org.apache.catalina.connector.Connector c = t.getConnector();
        c.setPort(0);
        c.setProperty("address", "127.0.0.1");
        org.apache.catalina.Context ctx = t.addContext("", base.toString());
        org.apache.catalina.startup.Tomcat.addServlet(ctx, "orders", servletClass);
        ctx.addServletMappingDecoded("/*", "orders");
        t.start();
        System.out.println("PORT=" + c.getLocalPort());
        System.out.flush();
        t.getServer().await();
    }
}
