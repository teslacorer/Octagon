FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src

# Copy POMs first to leverage Docker layer caching for deps
COPY pom.xml ./
COPY apidefender-core/pom.xml apidefender-core/pom.xml
COPY apidefender-scanners/pom.xml apidefender-scanners/pom.xml
COPY apidefender-reporting/pom.xml apidefender-reporting/pom.xml
COPY apidefender-cli/pom.xml apidefender-cli/pom.xml

# Pre-fetch dependencies (works without BuildKit cache mounts)
RUN mvn -q -e -B -DskipTests dependency:go-offline

# Now copy sources and build
COPY apidefender-core/ apidefender-core/
COPY apidefender-scanners/ apidefender-scanners/
COPY apidefender-reporting/ apidefender-reporting/
COPY apidefender-cli/ apidefender-cli/
RUN mvn -q -e -B -DskipTests -T 1C package

FROM eclipse-temurin:21-jre
ENV APP_HOME=/app \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"
WORKDIR $APP_HOME

# Install basic fonts to ensure PDF rendering works across locales
RUN set -e \
 && apt-get update \
 && apt-get install -y --no-install-recommends fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/apidefender-cli/target /tmp/cli-target
RUN set -e; f=$(ls -1 /tmp/cli-target/apidefender-cli-*.jar 2>/dev/null | grep -v "/original-" | head -n1); \
    echo "Using JAR: $f"; \
    mv "$f" /app/apidefender.jar; \
    rm -rf /tmp/cli-target

# POSIX shell wrapper (no bash dependency)
RUN printf '%s\n' '#!/usr/bin/env sh' \
    'set -e' \
    'exec java -Xms256m -Xmx1024m -jar /app/apidefender.jar "$@"' \
    > /usr/local/bin/apidefender \
 && chmod +x /usr/local/bin/apidefender

# Default locations used by README examples; also declare as volumes
RUN mkdir -p /app/specs /out /secrets
VOLUME ["/app/specs", "/out", "/secrets"]

ENTRYPOINT ["apidefender"]
CMD ["--help"]
