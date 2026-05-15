package org.isobit.app;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.HashSet;
import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import org.eclipse.microprofile.jwt.Claims;
import org.isobit.app.model.User;
import org.isobit.directory.model.People;
import org.isobit.util.Encrypter;
import org.isobit.util.SimpleException;
import org.isobit.util.XMap;
import org.isobit.util.XUtil;
import org.isobit.app.SessionService;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import org.eclipse.microprofile.jwt.JsonWebToken;
import jakarta.inject.Inject;
import java.util.UUID;

@Transactional
@ApplicationScoped
public class UserService2 {

    @Inject
    private JsonWebToken jwt;

    @Inject
    private JWTParser parser;

    @ConfigProperty(name = "mp.jwt.verify.issuer")
    private String ISSUER;

    private long REFRESH_TOKEN_SECONDS = 60 * 60 * 24 * 7; // week

    private long ACCESS_TOKEN_SECONDS = 3600;

    @Inject
    SessionService sessionService;

    public User getCurrentUser() {
        User user = new User();
        user.setUid(XUtil.intValue(jwt.getClaim("uid")));
        if (jwt.containsClaim("directory"))
            user.setDirectoryId(XUtil.intValue(jwt.getClaim("directory")));
        return user;
    }

    @PersistenceContext
    EntityManager em;

    static enum T {

        DATE,
        PASSWORD,
        URI_BRIEF,
        URI,
        LOGIN_URI,
        LOGIN_URL,
        PASS_RESET_URL,
        SITE,
        EDIT_URI,
        USERNAME,
        NAME,
        COMPLETE_NAME,
        MAILTO;

        private T() {
        }
    }

    static enum S {

        PREFIX,
        USER_EMAIL_VERIFICATION,
        REGISTER_ADMIN_CREATED,
        REGISTER_NO_APPROVAL_REQUIRED,
        REGISTER_PENDING_APPROVAL,
        REGISTER_PENDING_APPROVAL_ADMIN,
        STATUS_DELETED,
        STATUS_ACTIVATED,
        STATUS_BLOCKED,
        PASSWORD_RESET,
        USER_REGISTRATION_HELP;

        private S() {
        }
    }

    public List getList() {
        return em.createQuery("SELECT u FROM User u").getResultList();
    }

    public boolean changePassword(Integer uid, String currentPass, String newPass, String confirmPass) {
        // if (XUtil.isEmpty(newPass)) {
        // throw new RuntimeException("Contrase\u00f1a no puede ser en blanco");
        // }
        User u = em.find(User.class, uid);
        if (!newPass.equals(confirmPass)) {
            throw new RuntimeException("Contraseña nueva y su confirmacion deben ser iguales");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(currentPass.getBytes());
            System.out.println("currentPass=" + currentPass);
            currentPass = toHexadecimal(md.digest());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        if (!u.getPass().equals(currentPass)) {
            throw new RuntimeException("Contraseña actual ingresada no es la correcta");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(newPass.getBytes());
            newPass = toHexadecimal(md.digest());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        u.setPass(newPass);
        em.merge(u);
        return true;
    }

    private static String toHexadecimal(byte[] digest) {
        String hash = "";
        for (byte aux : digest) {
            int b = aux & 0xff;
            if (Integer.toHexString(b).length() == 1) {
                hash += "0";
            }
            hash += Integer.toHexString(b);
        }
        return hash;
    }

    public User login(String name, String pass) {
        User user = null;
        try {
            name = name.trim().toLowerCase();

            user = (User) em.createQuery(
                    "SELECT u FROM User u WHERE (LOWER(u.name)=:name OR LOWER(u.mail)=:name)")
                    .setParameter("name", name)
                    .getSingleResult();

            if (user != null) {
                long now = System.currentTimeMillis() / 1000;

                if (user.getStatus() == 0) {
                    throw new RuntimeException("User is disabled");
                }

                // -----------------------------------
                // RESET SI NO INTENTA DESDE HACE 5 MIN
                // (basado en login = último intento)
                // -----------------------------------
                if (user.getLogin() != 0 && (now - user.getLogin()) > 5 * 60) {
                    user.setThreshold((short) 0);
                }

                // -----------------------------------
                // BLOQUEO POR INTENTOS FALLIDOS
                // -----------------------------------
                if (user.getThreshold() >= 3) {
                    throw new RuntimeException("Too many failed attempts. Try later.");
                }

                // -----------------------------------
                // COOLDOWN (usa login, NO access)
                // -----------------------------------
                if (user.getLogin() != 0) {
                    long diff = now - user.getLogin();

                    if (diff < 3) {
                        user.setLogin(now); // reinicia cooldown
                        em.merge(user);
                        throw new RuntimeException("Wait 3 seconds before retry");
                    }
                }

                // -----------------------------------
                // PASSWORD CHECK
                // -----------------------------------
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.reset();
                md.update(pass.getBytes());

                String hashed = toHexadecimal(md.digest());
                boolean ok = user.getPass().equals(hashed);

                // SIEMPRE registrar intento
                user.setLogin(now);

                if (!ok) {
                    user.setThreshold((short) (user.getThreshold() + 1));
                    em.merge(user);
                    return null;
                }

                // -----------------------------------
                // LOGIN EXITOSO
                // -----------------------------------
                user.setThreshold((short) 0);
                user.setAccess((int) now); // ✔ último login exitoso
                em.merge(user);
            }

        } catch (NoResultException e) {
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return user;
    }

    public Map<String, ?> getJWTInfoByUser(User user, Long ttlSeconds) {
        String accessJti = UUID.randomUUID().toString();
        String refreshJti = UUID.randomUUID().toString();
        JwtClaimsBuilder jwtClaimsBuilder = Jwt.issuer(ISSUER)
                .upn("jdoe@quarkus.io")
                .groups(new HashSet<>(Arrays.asList("User", "Admin")))
                .expiresIn(ttlSeconds==null?ACCESS_TOKEN_SECONDS:Math.min(ttlSeconds,ACCESS_TOKEN_SECONDS)) // 11min
                .claim("jti", accessJti)
                .claim("uid", user.getUid());

        if (user.getDirectoryId() != null) {
            People people = em.find(People.class, user.getDirectoryId());
            jwtClaimsBuilder = jwtClaimsBuilder
                    .claim("fullName", people.getFullName())
                    .claim("directory", user.getDirectoryId());
        }

        String token = jwtClaimsBuilder.claim("user", user.getName())
                .claim(Claims.birthdate.name(), "2001-07-13")
                .sign();
        // =========================
        // REFRESH TOKEN (largo)
        // =========================

        String refreshToken = Jwt.issuer(ISSUER)
                .upn(user.getName())
                .expiresIn(ttlSeconds==null?REFRESH_TOKEN_SECONDS:Math.min(ttlSeconds*4,REFRESH_TOKEN_SECONDS)) // 7 días
                .claim("jti", refreshJti)
                .claim("uid", user.getUid())
                .claim("type", "refresh")
                .sign();
        HashMap<String, Object> result = new HashMap<String, Object>();
        result.put("token", token);
        result.put("refreshToken", refreshToken);
        result.put("user", user.getName());
        result.put("user_nicename", user.getName());
        if (user.getDirectoryId() != null) {
            result.put("directory", user.getDirectoryId().toString());
            People people = em.find(People.class, user.getDirectoryId());
            if (people != null) {
                result.put("fullName", people.getFullName());
            }
        }
        List<Integer> roles = em.createQuery("SELECT ur.role.rid FROM UserRole ur WHERE ur.PK.uid=:uid", Integer.class)
                .setParameter("uid", user.getUid())
                .getResultList();
        roles.add(0);
        result.put("perms", em.createQuery("SELECT p.perm FROM Permission p WHERE p.role.rid IN :rid", String.class)
                .setParameter("rid", roles)
                .getResultList().stream()
                .flatMap(permission -> Arrays.stream(permission.split(",")))
                .collect(Collectors.toList()));
        //sessionService.put(accessJti, "status", "active", ACCESS_TOKEN_SECONDS);
        //sessionService.put(refreshJti, "refresh", "active", REFRESH_TOKEN_SECONDS);
        return result;
    }

    public String refreshToken(String refreshToken, Long ttlSeconds) {
        try {
            // 🔥 parsear el refresh token correctamente
            JsonWebToken jwt = parser.parse(refreshToken);

            String jti = jwt.getClaim("jti");
            Integer uid = XUtil.intValue(jwt.getClaim("uid"));
            String type = jwt.getClaim("type");

            // ✔ validar que sea refresh token
            if (!"refresh".equals(type)) {
                throw new RuntimeException("Invalid token type");
            }

            // ✔ validar sesión (opcional redis)
            //sessionService.refresh(jti, ACCESS_TOKEN_SECONDS);

            // ✔ generar NUEVO access token (nuevo jti recomendado)
            String newJti = UUID.randomUUID().toString();
            String newToken = Jwt.issuer(ISSUER)
                    .upn(jwt.getClaim("upn"))
                    .subject(jwt.getSubject())
                    .claim("jti", newJti)
                    .claim("uid", uid)
                    .groups(jwt.getGroups())
                    .expiresIn( Math.min(ttlSeconds, ACCESS_TOKEN_SECONDS))
                    .sign();

            return newToken;

        } catch (Exception e) {
            throw new RuntimeException("Invalid refresh token");
        }
    }

    // @Override
    public int password(Map m) throws Exception {
        String name = (String) m.get("name");
        User user = null;
        try {
            user = (User) em
                    .createQuery("SELECT u FROM User u WHERE (LOWER(u.name)=:name OR LOWER(u.mail)=:name)", User.class)
                    .setParameter("name", name.toLowerCase()).getSingleResult();
        } catch (NoResultException n) {
            // Si no se encuentra registro se intenta otros componentes
            /*
             * for (String mn : getModuleNameList()) {
             * if (user != null) {
             * break;
             * }
             * try {
             * user = this.getModule(UserFacadeLocal.UserModule.class, mn).password(m);
             * } catch (SimpleException e) {
             * //throw e;
             * } catch (RuntimeException e) {
             * X.log(e.getMessage());
             * }
             * }
             */
        }
        if (user != null && user.getStatus() > 0) {
            if (!this.mailNotify(m, S.PASSWORD_RESET.toString(), user, "es")) {
                throw new SimpleException("Ha sucedido un error al enviar informacion por correo.");
            }
        } else {
            throw new SimpleException(
                    "El codigo de usuario o correo no se encuentra registrado o esta inactivo, comuniquese con el administrador.");
        }
        return 0;
    }

    public String passResetUrl(User account) {
        long passResetTimestamp = X.getServerDate().getTime() / 1000;
        return "";/*
                   * X.url("user/reset/" + account.getUid() + "/" + passResetTimestamp + "/"
                   * + this.passRehash(account.getPass(), passResetTimestamp,
                   * account.getLogin()));
                   */
    }

    private String passRehash(String pass, long timestamp, long login) {
        return new Encrypter().encode(Encrypter.MD5, pass + timestamp + login);
    }

    public Object getTokenByCode(String code) {
        try {
            Object[] row = (Object[]) em.createNativeQuery("SELECT client_id,user_id FROM oauth2_code WHERE code=:code")
                    .setParameter("code", code).setMaxResults(1).getSingleResult();
            Integer uid = Integer.parseInt(row[1].toString());
            User user = em.find(User.class, uid);
            em.createNativeQuery("DELETE FROM oauth2_code WHERE code=:code")
                    .setParameter("code", code).executeUpdate();

            return getJWTInfoByUser(user, null);
        } catch (Exception ex) {

            HashMap<String, Object> map = new HashMap<String, Object>();
            if (ex instanceof jakarta.persistence.NoResultException) {
                map.put("msg", "No Found");
            } else {
                ex.printStackTrace();
                map.put("msg", ex.toString());
            }
            return map;
        }
    }

    private boolean mailNotify(Map m, String op, User account, String language) {
        boolean default_notify = !op.equals(S.STATUS_DELETED.toString()) && !op.equals(S.STATUS_BLOCKED.toString());
        boolean notify = true;// XUtil.booleanValue(systemFacade.getV(USER_MAIL_ + op + "_notify",
                              // default_notify));
        if (notify) {
            XMap params = new XMap("account", account);
            if (XUtil.intValue(account.getDirectoryId()) != 0) {
                try {
                    m.put(T.NAME,
                            em.createQuery("SELECT p.names FROM People p WHERE p.id=:peopleId")
                                    .setParameter("peopleId", (Object) account.getDirectoryId()).getSingleResult()
                                    .toString().split(" ")[0]);
                } catch (NoResultException noResultException) {
                    // empty catch block
                }
            } else {
                People people = (People) m.get("people");
                if (people != null) {
                    m.put(T.NAME, ("" + people.getNames()).split(" ")[0]);
                }

            }
            m.put("account", account);
            /*
             * contactFacade.mail(m, this, op, account.getMail(), language, params);
             * if (op.equals(S.REGISTER_PENDING_APPROVAL.toString())) {
             * contactFacade.mail(
             * m, this,
             * S.REGISTER_PENDING_APPROVAL_ADMIN.toString(),
             * systemFacade.getV("site_mail", "").toString(),
             * language,
             * params
             * );
             * }
             */
        }
        return true;
    }

    public Map can(Integer uid, String[] perms) {

        List<String> persList = em.createQuery(
                "SELECT DISTINCT CONCAT(',',p.perm,',') FROM UserRole ur INNER JOIN Permission p ON ur.PK.rid=p.role.rid WHERE ur.PK.uid=:uid",
                String.class).setParameter("uid", uid).getResultList();
        HashMap mm = new HashMap();
        for (String perm : perms) {
            mm.put(perm, persList.stream().anyMatch(a -> a.contains("," + perm + ",")));
        }
        return mm;
    }

    public Object perms(Integer uid) {
        return em.createQuery(
                "SELECT DISTINCT CONCAT(',',p.perm,',') FROM UserRole ur INNER JOIN Permission p ON ur.PK.rid=p.role.rid WHERE ur.PK.uid=:uid",
                String.class)
                .setParameter("uid", uid)
                .getResultStream().flatMap(Pattern.compile(",")::splitAsStream)
                .map(String::trim).distinct()
                .collect(Collectors.toList());

    }

}
