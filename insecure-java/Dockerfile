# Build stage
FROM gradle:7.6.1-jdk17 AS build
WORKDIR /app
COPY . .
RUN gradle build --no-daemon

# Run stage
FROM openjdk:17-slim
WORKDIR /app
COPY --from=build /app/build/libs/insecure-java-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Create a non-root user to run the application
RUN groupadd -r javauser && useradd -r -g javauser javauser
RUN chown -R javauser:javauser /app
USER javauser

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

