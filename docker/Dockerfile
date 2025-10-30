# syntax=docker/dockerfile:1.6

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml ./
COPY apidefender-core/pom.xml apidefender-core/pom.xml
COPY apidefender-scanners/pom.xml apidefender-scanners/pom.xml
COPY apidefender-reporting/pom.xml apidefender-reporting/pom.xml
COPY apidefender-cli/pom.xml apidefender-cli/pom.xml
# pre-fetch deps
RUN --mount=type=cache,target=/root/.m2 mvn -q -e -DskipTests dependency:go-offline
COPY apidefender-core/ apidefender-core/
COPY apidefender-scanners/ apidefender-scanners/
COPY apidefender-reporting/ apidefender-reporting/
COPY apidefender-cli/ apidefender-cli/
RUN --mount=type=cache,target=/root/.m2 mvn -q -e -DskipTests -T 1C package

FROM eclipse-temurin:21-jre
ENV APP_HOME=/app
WORKDIR $APP_HOME
COPY --from=build /src/apidefender-cli/target /tmp/cli-target
RUN set -e; f=$(ls -1 /tmp/cli-target/apidefender-cli-*.jar 2>/dev/null | grep -v "/original-" | head -n1); echo "Using JAR: $f"; mv "$f" /app/apidefender.jar; rm -rf /tmp/cli-target
RUN echo '#!/usr/bin/env bash' > /usr/local/bin/apidefender \
    && echo 'set -e' >> /usr/local/bin/apidefender \
    && echo 'exec java -Xms256m -Xmx1024m -jar /app/apidefender.jar "$@"' >> /usr/local/bin/apidefender \
    && chmod +x /usr/local/bin/apidefender

# default locations used by README examples
RUN mkdir -p /app/specs /out /secrets
ENTRYPOINT ["apidefender"]
CMD ["--help"]
