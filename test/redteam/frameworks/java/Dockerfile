# Red team round 3: Spring Boot 3.3 (embedded Tomcat) + traffic-twin Java agent
# (-javaagent from the init image deploy/images/sdk-java, appended to
# JAVA_TOOL_OPTIONS as the injector does). No change to the application.
# Build: test/redteam/frameworks/build_images.sh java
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY test/redteam/frameworks/java/pom.xml ./
RUN mvn -B -q dependency:go-offline
COPY test/redteam/frameworks/java/src ./src
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a
COPY --from=rt3fw-sdk-java:local /sdk/java /tt/sdk/java
COPY --from=build /src/target/app.jar /app/app.jar
RUN useradd -m -u 10001 app && install -d -o app -g app -m 0700 /var/lib/tt-state
USER app
ENV JAVA_TOOL_OPTIONS="-javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar"
EXPOSE 8080
CMD ["java", "-jar", "/app/app.jar", "--server.port=8080"]
