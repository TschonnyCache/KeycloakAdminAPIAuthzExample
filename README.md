# KeycloakAdminAPIAuthzExample
A small example on how to use the keycloak admin api for authorization tasks such as creating resources, policies, permissions and roles

This uses the keycloak instance from the keycloak-quickstart tutorial app-authz-springboot https://github.com/keycloak/keycloak-quickstarts/tree/latest/app-authz-springboot

The szenario of this example is the following:
A resource server is using the keycloak-spring-boot-starter adapter for authentification and authorization,
which means it has the following lines in ints application.properties:

keycloak.realm=spring-boot-quickstart  
keycloak.auth-server-url=http://localhost:8180/auth  
keycloak.ssl-required=external  
keycloak.resource=app-authz-springboot  
keycloak.public-client=false  
keycloak.credentials.secret=secret  
keycloak.policy-enforcer-config.on-deny-redirect-to=/api/accessDenied  

The last line will make the resource server cache the authorization policies and it's paths from keycloak.
The resource server is serving some files und the path /api/data-offer/{data-offer-number}

The KeycloakAdminController class can now be used to dynamically add authoriziation for resources
of the resource server. i.e. if a new file is added, the class can be used to permit access to 
a user for the new file dynamically.
