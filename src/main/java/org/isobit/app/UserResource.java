package org.isobit.app;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.isobit.app.jpa.User;

import java.util.HashMap;
import java.util.Map;

@Path("")
@RequestScoped
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class UserResource {

	@Inject
	UserService userService;

	@Inject
	JsonWebToken jwt;

	@POST()
	@Path("d")
	@PermitAll
	public String login() {
		return "POST";
	}
	
	@POST()
	@Path("can")
	@PermitAll
	public Object can(String[] perms) {
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		return userService.can(uid,perms);
	}

	@POST()
	@Path("")
	@PermitAll
	public Object login(Map<String,Object> m) {
		String username = (String) m.get("username");
		String password = (String) m.get("password");
		if (username == null || username.trim().length() == 0)
			throw new RuntimeException("Username is Empty!");
		if (password == null || password.trim().length() == 0)
			throw new RuntimeException("Password is Empty!");
		User user = userService.login(username, password);
		if (user == null)
			throw new RuntimeException("Usuario no valido!");
		return userService.getJWTInfoByUser(user);
	}

	@POST()
	@Path("/token")
	@PermitAll
	@Consumes(MediaType.TEXT_PLAIN)
	public Object getTokenByCode(String code) {
		return userService.getTokenByCode(code);
	}



	@POST()
	@Path("change-password")
	//@RolesAllowed({ "User", "Admin" })
	@PermitAll
	public Object changePassword(Map<Object, String> map) {
		/* User user = userService.getCurrentUser(); */
		System.out.println(map);
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		// userService.initSession(uid);
		HashMap<String,Object> m = new HashMap<String,Object>();
		m.put("changed", userService.changePassword(uid, map.get("current"), map.get("new"), map.get("confirm")));
		return m;
	}


	@POST
	@Path("password")
	@PermitAll
    public Object password(Map<Object, Object> map) throws Exception {
        int result = userService.password(map);
        //Object destiny = sessionFacade.get(X.DESTINY);
        //sessionFacade.put(X.DESTINY, null);
        //m.put(destiny, destiny);
        //String d = (destiny != null ? destiny : "admin").toString();
        org.isobit.app.jpa.User user = (org.isobit.app.jpa.User) map.get("account");
        map = new HashMap<Object, Object>();
        if (user != null) {
            map.put("message", "Se envio un mensaje de cambio de contraseña a su e-mail.");
        	map.put("OK", true);
        } else {
            map.put("OK", false);
        }
        return map;
    }




	@GET()
	@Path("")
	@PermitAll
	public Object checkToken(@Context SecurityContext ctx) {
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		HashMap<String,Object> result=new HashMap<String,Object>();
		result.put("uid",uid);
		return result;
	}

	@GET
	@Path("roles-allowed")
	@RolesAllowed({ "User", "Admin" })
	public Object helloRolesAllowed(@Context SecurityContext ctx) {
		return getResponseString(ctx) + ", birthdate: " + jwt.getClaim("birthdate").toString()
				+ ", uid: " + jwt.getClaim("uid");
	}

	private String getResponseString(SecurityContext ctx) {
		String name;
		if (ctx.getUserPrincipal() == null) {
			name = "anonymous";
		} else if (!ctx.getUserPrincipal().getName().equals(jwt.getName())) {
			throw new InternalServerErrorException("Principal and JsonWebToken names do not match");
		} else {
			name = ctx.getUserPrincipal().getName();
		}
		return String.format("hello + %s," + " isHttps: %s," + " authScheme: %s," + " hasJWT: %s", name, ctx.isSecure(),
				ctx.getAuthenticationScheme(), hasJwt());
	}

	private boolean hasJwt() {
		return jwt.getClaimNames() != null;
	}
}