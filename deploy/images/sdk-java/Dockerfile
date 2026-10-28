# syntax=docker/dockerfile:1
#
# SDK init image for the JVM (Java 17+). Layout copied into /tt/sdk/java:
#   lib/sdk.jar                  Jakarta servlet filter and client wrappers
#   lib/sdk-servlet-javax.jar    javax.servlet variant
#   agent/traffic-twin-agent.jar the -javaagent (zero-code injection; no dependencies)
#   ext/sdk-otel-extension.jar   extension for the OpenTelemetry Java agent
# The two lib jars go on the application classpath (opt-in, see
# traffic-twin.io/java-classpath); the extension is only for the OTel agent
# and is deliberately not on the classpath.
#
# Build from the repository root:
#   docker build -f deploy/images/sdk-java/Dockerfile -t ghcr.io/ivseb/traffic-twin/sdk-java:0.1.1 .
#
# Base images are pinned by digest; bump tag and digest together.

FROM --platform=$BUILDPLATFORM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a AS build
WORKDIR /src/sdk/java
COPY sdk/java/ ./
RUN ./mvnw -B -q -DskipTests package

FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
LABEL org.opencontainers.image.title="traffic-twin sdk-java (init image)" \
      org.opencontainers.image.source="https://github.com/ivseb/traffic-twin" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /src/sdk/java/sdk/target/sdk-0.1.1.jar /sdk/java/lib/sdk.jar
COPY --from=build /src/sdk/java/sdk-servlet-javax/target/sdk-servlet-javax-0.1.1.jar /sdk/java/lib/sdk-servlet-javax.jar
COPY --from=build /src/sdk/java/sdk-otel-extension/target/sdk-otel-extension-0.1.1.jar /sdk/java/ext/sdk-otel-extension.jar
COPY --from=build /src/sdk/java/sdk-agent/target/traffic-twin-agent-0.1.1.jar /sdk/java/agent/traffic-twin-agent.jar
USER 65532:65532
ENTRYPOINT ["cp", "-R", "/sdk/.", "/tt/sdk/"]
