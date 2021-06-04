import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.*;

import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

public class KeycloakAdminController {

    AuthorizationResource authRep = null;
    RealmResource realm = null;
    Keycloak keycloakInstance = null;
    String realmName = "spring-boot-quickstart";
    String resourceServerClientId = null;
    String kcHost = "localhost:8180";

    public KeycloakAdminController() {
        keycloakInstance = Keycloak.getInstance(
                "http://"+ kcHost +"/auth",
                "master",
                "admin",
                "admin",
                "admin-cli");

        realm = keycloakInstance.realm("spring-boot-quickstart");
        ClientsResource clients = realm.clients();
        List<ClientRepresentation> query_result = clients.findByClientId("app-authz-springboot");
        ClientRepresentation app_authz_springboot_client = query_result.get(0);
        resourceServerClientId = app_authz_springboot_client.getId();
        authRep = realm.clients().get(resourceServerClientId).authorization();
    }

    public void DoSomething() {
        try {
            permitUserToDataOffer("1234","alice");
            permitUserToDataOffer("1234","jdoe");
            //createPremiumUserRoleAndPolicy();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("End");
    }

    public void permitUserToDataOffer(String dataOfferId, String userName) throws Exception {
        String resourceName = "Data Offer " + dataOfferId;
        String resourceId = getOrCreateResource(dataOfferId,resourceName);

        // The policies are all named according to this pattern so its easy to find them
        String policyName = "Permit policy for data offer " + dataOfferId;
        String policyId = getPolicyId(policyName);
        String userId = getIdForUserName(userName);
        // If there is no policy we need to create it
        if(policyId == null){
            policyId = createPolicy(userName, dataOfferId, policyName);
            // And after it was created we need to link it to the policy with a permission
            createPermission(resourceId,policyId,resourceName);
        } else {
            // If a policy for the data offer allready exists, we can just add the user to it
            addUserToPolicy(userId,policyName);
        }
    }

    public String createPolicy(String userId, String dataOfferId, String policyName) throws Exception {

        PolicyRepresentation newPolicy = new PolicyRepresentation();
        newPolicy.setName(policyName);
        newPolicy.setType("user");
        newPolicy.setDescription("Policy to permit multiple users to data offer " + dataOfferId);
        Map<String, String> config = new HashMap<>();
        config.put("users","[\"" + userId + "\"]");
        newPolicy.setConfig(config);
        newPolicy.setLogic(Logic.POSITIVE);
        newPolicy.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        authRep.policies().create(newPolicy);
        return getPolicyId(policyName);
    }

    private String getPolicyId(String policyName){
        String policyId = null;
        for(PolicyRepresentation polRep : authRep.policies().policies()){
            if(polRep.getName().equals(policyName)){
                policyId = polRep.getId();
            }
        }
        return policyId;
    }

    public String getIdForUserName(String username) throws Exception {
        String id = null;
        List<UserRepresentation> result = realm.users().search(username);
        for(UserRepresentation user : result) {
            if(user.getUsername().equals(username)){
                id = user.getId();
            }
        }
        if (id == null){
            throw new Exception("User not found");
        }
        return id;
    }

    public String getIdForResource(String resourceName){
        String resouceId = null;
        for(ResourceRepresentation resource: authRep.resources().resources()){
            if(resource.getName().equals(resourceName)){
                resouceId = resource.getId();
            }
        }
        return resouceId;
    }

    public String getOrCreateResource(String dataOfferId, String resourceName){
        String uri = "/api/data-offer/"+dataOfferId;
        String resourceId = getIdForResource(resourceName);

        if(resourceId == null){
            ResourceRepresentation newResource = new ResourceRepresentation();
            newResource.setName(resourceName);
            newResource.setDisplayName(resourceName);
            newResource.setType("urn:de4l:data_offer");
            newResource.setUris(Collections.singleton(uri));
            authRep.resources().create(newResource);
            resourceId = getIdForResource(resourceName);
        }
        return resourceId;
    }

    public String createPermission(String resourceId, String policyId, String resourceName){
        String permissionName = "Permission for resource " + resourceName;
        String permissionId = null;
        String premiumPolicyId = authRep.policies().findByName("Premium User Policy").getId();
        Set<String> policiesSet = Set.of(policyId, premiumPolicyId);

        //Creating permission
        PolicyRepresentation newPermission = new PolicyRepresentation();
        newPermission.setName(permissionName);
        newPermission.setDescription("");
        newPermission.setType("resource");
        newPermission.setLogic(Logic.POSITIVE);
        newPermission.setResources(Collections.singleton(resourceId));
        newPermission.setPolicies(policiesSet);
        newPermission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        authRep.policies().create(newPermission);
        //getting permission id
        for(PolicyRepresentation permissionRep : authRep.policies().policies()){
            if(permissionRep.getName().equals(permissionName)){
                permissionId = permissionRep.getId();
            }
        }
        return permissionId;
    }

    public Response makeHTTPRequest(String path, String json, String method){
        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target(path);
        Invocation.Builder request = resource.request();
        AccessTokenResponse token = keycloakInstance.tokenManager().getAccessToken();
        request.header("Authorization", "Bearer " + token.getToken());
        if(method.equals("PUT")){
            return request.put(Entity.entity(json, MediaType.APPLICATION_JSON));
        }else{
            return request.post(Entity.entity(json, MediaType.APPLICATION_JSON));
        }

    }

    // This is a inital setup and only needs to be run once for a new resource server client
    public void createPremiumUserRoleAndPolicy(){

        //Creating the premium role
        String path = "http://"+ kcHost +"/auth/admin/realms/"+ realmName +"/roles";
        String json = "{\"name\":\"user-premium\"}";
        makeHTTPRequest(path,json,"POST");

        //Getting the id of premium
        RoleResource userPremiumRoleRep = realm.roles().get("user-premium");
        String roleID = userPremiumRoleRep.toRepresentation().getId();

        // Creating premium policy
        path = "http://"+ kcHost +"/auth/admin/realms/"+
                realmName +
                "/clients/"+
                resourceServerClientId +
                "/authz/resource-server/policy/role/";
        json = "{\"type\":\"role\",\"logic\":\"POSITIVE\",\"decisionStrategy\":\"UNANIMOUS\"," +
                "\"name\":\"Premium User Policy\",\"roles\":[{\"id\":\""+roleID+"\"}]}";

        makeHTTPRequest(path,json,"POST");
    }

    public void addUserToPolicy(String userID, String policyName) throws Exception {

        String policyId = getPolicyId(policyName);
        String path = "http://"+ kcHost +"/auth/admin/realms/"+
                realmName +
                "/clients/"+
                resourceServerClientId +
                "/authz/resource-server/policy/user/" +
                policyId;
        PolicyRepresentation existingPolicy = authRep.policies().findByName(policyName);
        Map<String, String> config = existingPolicy.getConfig();
        String existingUsers = config.get("users");
        String existingUsersBraketsRemoved = existingUsers.substring(0, existingUsers.length()-1);
        String json = "{\"id\":\""+ existingPolicy.getId()+
                "\",\"name\":\""+ existingPolicy.getName() +
                "\",\"description\":\" "+ existingPolicy.getDescription()+
                "\",\"type\":\"user\",\"logic\":\"POSITIVE\",\"decisionStrategy\":\"UNANIMOUS\",\"users\":" +
                existingUsersBraketsRemoved+",\"" + userID + "\"]}";
        makeHTTPRequest(path,json,"PUT");
    }
}

