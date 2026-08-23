# KavachX sandbox image — Java / Kotlin targets.
#
# Selected automatically when the detected project language is java/kotlin (app/sandbox/images.py).
# Same isolation as every other sandbox image; only the toolchain differs. A JDK plus Maven is
# present so `mvn`/`./mvnw`/`./gradlew` builds run in the writable, networked build phase, and the
# built artifact can be executed in the locked-down execute phase.
#
# Build:
#   docker build -f sandbox/Dockerfile.java -t kavachx/sandbox-java:dev sandbox

FROM eclipse-temurin:21-jdk

# Maven for `mvn` projects. Gradle projects almost always ship the `./gradlew` wrapper, which needs
# only the JDK, so gradle itself is deliberately not installed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      maven \
 && rm -rf /var/lib/apt/lists/* \
 # The execute phase gives the container no interface; drop the network tools the base image ships.
 && rm -f /usr/bin/curl /usr/bin/wget /usr/bin/nc /usr/bin/telnet 2>/dev/null || true

# Maven's local repository lives under HOME, which the adapter redirects to the writable tmpfs.
ENV MAVEN_OPTS="-Dmaven.repo.local=/workspace/.tmp/.m2/repository"

WORKDIR /workspace

# nobody in the execute phase; the adapter overrides to the host uid for the writable build phase.
USER 65534:65534

CMD ["java", "-version"]
