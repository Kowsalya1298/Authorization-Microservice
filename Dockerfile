FROM amazoncorretto:8
EXPOSE 9090
ADD target/*.jar authorization-microservice-0.0.1-SNAPSHOT
ENTRYPOINT ["sh","-c","java -jar /authorization-microservice-0.0.1-SNAPSHOT.jar"]
