package org.isobit.app;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.*;

//import io.quarkus.security.identity.SecurityIdentity;

@Path("/hello")
public class UserRESTService {

    @Inject
    UserService service;

    //@Inject
    //SecurityIdentity securityIdentity;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Object hello() {
        return new File(".").list();
    }

    @GET
    @Path("/0/0")
    @Produces(MediaType.APPLICATION_JSON)
    public Object getList() {
        return service.getList();
    }
    

   /* @GET
    @Path("/me")
    @RolesAllowed("user")
    @NoCache
    public User me() {
        //return new User(securityIdentity);
    }
*/
    public static class User {

        //private final String userName;

        /*User(SecurityIdentity securityIdentity) {
            this.userName = securityIdentity.getPrincipal().getName();
        }

        public String getUserName() {
            return userName;
        }*/
    }

}