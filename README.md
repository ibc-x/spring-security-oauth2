# spring-security-oauth2

- Ajouter la depandance suivante dans votre fichier pom.xml:
 ```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

- Creer un premier utilisateur, dans postman ou autre client http:
Endpoit: http://localhost:8080/api/v1/auth/register
```
 {
    "username":"coun",
    "password":"coum",
    "fullName":"Councoumbré"
}
```