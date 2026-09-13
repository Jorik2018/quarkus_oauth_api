package org.isobit.app.controller;

import jakarta.annotation.security.PermitAll;
import io.quarkus.security.Authenticated;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.NewCookie.SameSite;

import org.isobit.app.UserService2;
import org.isobit.app.model.User;
import org.eclipse.microprofile.jwt.JsonWebToken;
import java.util.HashMap;
import java.util.Map;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.core.NewCookie;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import jakarta.ws.rs.QueryParam;
import jakarta.inject.Inject;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import org.jboss.logging.Logger;
import org.isobit.app.client.CaptchaClient;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import org.jboss.logging.Logger;

@Path("")
@RequestScoped
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
public class UserController {

	@Inject
	UserService2 userService;

	@Inject
	JsonWebToken jwt;

	@Inject
	@RestClient
	CaptchaClient captchaClient;

	private static final Logger LOG = Logger.getLogger(UserController.class);

	private final KeyCommands<String> redisKeys;
	private final ValueCommands<String, String> redisValues;

	@Inject
	public UserController(RedisDataSource redisDataSource) {
		this.redisKeys = redisDataSource.key();
		this.redisValues = redisDataSource.value(String.class);
	}

	@POST()
	@Path("can")
	@PermitAll
	public Object can(String[] perms) {
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		return userService.can(uid, perms);
	}

	@POST()
	@Path("perms")
	public Object perms() {
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		return userService.perms(uid);
	}

	@POST
	@Path("")
	@PermitAll
	public Object login(Map<String, Object> m) {

		String username = (String) m.get("name");
		String password = (String) m.get("pass");

		if (username == null || username.isBlank()) {
			username = (String) m.get("username");
		}

		if (password == null || password.isBlank()) {
			password = (String) m.get("password");
		}
		String ttlSeconds = (String) m.get("ttlSeconds");

		if (username == null || username.trim().isEmpty())
			throw new BadRequestException("Username is Empty!");

		if (password == null || password.trim().isEmpty())
			throw new BadRequestException("Password is Empty!");

		String captchaId = (String) m.get("captchaId");
		String captcha = (String) m.get("captcha");
		if (captchaId == null || captchaId.isBlank())
			throw new BadRequestException("CaptchaId is Empty!");

		if (captcha == null || captcha.isBlank())
			throw new BadRequestException("Captcha is Empty!");

		validateCaptcha(
				captchaId,
				captcha);

		User user = userService.login(username, password);

		if (user == null)
			throw new BadRequestException("Usuario no válido!");

		Map<String, ?> result = userService.getJWTInfoByUser(user,
				ttlSeconds != null ? Long.valueOf(ttlSeconds) : null);

		// 🔹 extraer refresh token del map
		String refreshToken = (String) result.get("refreshToken");

		// 🔹 removerlo del body (opcional pero recomendado)
		result.remove("refreshToken");
		// NewCookie cannot be resolved to a type
		return Response.ok(result)
				.cookie(new NewCookie.Builder("refreshToken")
						.value(refreshToken)
						.path("/")
						.maxAge(60 * 60 * 24 * 7)
						.httpOnly(true)
						.sameSite(SameSite.LAX) // 🔥 CLAVE
						.secure(false)// for prod must be true
						.build())
				.build();
	}

	private void validateCaptcha(
			String captchaId,
			String captcha) {

		String key = "captcha:" + captchaId;

		try {

			String expected = redisValues.get(key);

			if (expected == null) {
				throw new BadRequestException(
						"Captcha no válido!");
			}

			if (!expected.equalsIgnoreCase(
					captcha.trim())) {
				throw new BadRequestException(
						"Captcha no válido!");
			}

			if (!key.endsWith("+test")) {
				redisKeys.del(key);
			}
		} catch (BadRequestException e) {

			throw e;

		} catch (Exception e) {

			LOG.error(
					"Error conectando con Redis. "
							+ "Se continúa con login normal sin validar captcha.",
					e);

			// NO lanzamos excepción.
			// Continúa el login user/password.
		}
	}

	@POST()
	@Path("/token")
	@PermitAll
	@Consumes(MediaType.TEXT_PLAIN)
	public Object getTokenByCode(String code) {
		return userService.getTokenByCode(code);
	}

	@POST
	@Path("/validate")
	@Produces(MediaType.APPLICATION_JSON)
	public Response validate(
			@CookieParam("refreshToken") String refreshToken,
			@QueryParam("ttlSeconds") Long ttlSeconds) {
		return refresh(refreshToken, ttlSeconds);
	}

	@POST
	@Path("/refresh")
	@Produces(MediaType.APPLICATION_JSON)
	@PermitAll
	public Response refresh(
			@CookieParam("refreshToken") String refreshToken,
			@QueryParam("ttlSeconds") Long ttlSeconds) {

		if (refreshToken == null || refreshToken.isBlank()) {
			return Response.status(Response.Status.UNAUTHORIZED)
					.entity(Map.of("error", "Missing refresh cookie"))
					.build();
		}

		try {
			String newAccessToken = userService.refreshToken(refreshToken, ttlSeconds);

			return Response.ok(Map.of(
					"token", newAccessToken,
					"type", "Bearer")).build();

		} catch (Exception e) {
			e.printStackTrace();

			return Response.status(Response.Status.UNAUTHORIZED)
					.entity(Map.of(
							"error",
							"Invalid or expired refresh token"))
					.build();
		}
	}

	@POST()
	@Path("change-password")
	// @RolesAllowed({ "User", "Admin" })
	public Object changePassword(Map<Object, String> map) {
		/* User user = userService.getCurrentUser(); */
		System.out.println(map);
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		// userService.initSession(uid);
		HashMap<String, Object> m = new HashMap<String, Object>();
		m.put("changed", userService.changePassword(uid, map.get("current"), map.get("new"), map.get("confirm")));
		return m;
	}

	@POST
	@Path("password")
	@PermitAll
	public Object password(Map<Object, Object> map) throws Exception {
		int result = userService.password(map);
		// Object destiny = sessionFacade.get(X.DESTINY);
		// sessionFacade.put(X.DESTINY, null);
		// m.put(destiny, destiny);
		// String d = (destiny != null ? destiny : "admin").toString();
		org.isobit.app.model.User user = (org.isobit.app.model.User) map.get("account");
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
	@Path("info")
	public Object checkToken(@Context SecurityContext ctx) {
		Integer uid = Integer.parseInt(jwt.getClaim("uid").toString());
		HashMap<String, Object> result = new HashMap<String, Object>();
		result.put("uid", uid);
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