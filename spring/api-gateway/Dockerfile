FROM openjdk:17-jdk-alpine

ADD target/api-gateway*.jar /usr/local/app.jar
ENTRYPOINT ["java", "-jar", "/usr/local/app.jar"]
