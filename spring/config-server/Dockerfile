FROM openjdk:17-jdk-alpine

ADD target/*.jar /usr/local/app.jar
ENTRYPOINT ["java", "-jar", "/usr/local/app.jar"]
