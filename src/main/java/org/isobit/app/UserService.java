package org.isobit.app;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.HashSet;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.eclipse.microprofile.jwt.Claims;
import org.isobit.app.jpa.Permission;
import org.isobit.app.jpa.User;

import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

@Transactional
@ApplicationScoped
public class UserService {

    @PersistenceContext
    EntityManager em;

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
            throw new RuntimeException("Contrase\u00f1a actual ingresada no es la correcta");
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
            user = (User) em.createQuery("SELECT u FROM User u WHERE (LOWER(u.name)=:name OR LOWER(u.mail)=:name)")
                    .setParameter("name", name).getSingleResult();
            if (user != null) {
                if (user.getStatus() == 0) {
                    throw new RuntimeException("User is disabled");
                }
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.reset();
                md.update(pass.getBytes());
                if (!user.getPass().equals(toHexadecimal(md.digest())))
                    return null;
            }
        } catch (NoResultException noResultException) {
            // X.log("Failed attemp for " + name + " using " + pass + "=" + new
            // Encrypter().encode(Encrypter.MD5, pass));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        // X.log("userFacade.user=" + user);
        /*
         * for (String mn : getModuleNameList()) {
         * if (user != null) {
         * break;
         * }
         * try {
         * user = getModule(UserModule.class, mn).login(name, pass, m);
         * X.log("Iniciando session usando " + mn + " resulta user=" + user);
         * } catch (RuntimeException e) {
         * X.log(e);
         * }
         * }
         */
        if (user != null) {
            // this.authenticateFinalize(user);
        }
        return user;
    }

    public Map getJWTInfoByUser(User user) {
        JwtClaimsBuilder jwtClaimsBuilder = Jwt.issuer("https://example.com/issuer")
                .upn("jdoe@quarkus.io")
                .groups(new HashSet<>(Arrays.asList("User", "Admin")))
                .expiresIn(60 * 60)
                .claim("uid", user.getUid());
        if (user.getIdDir() != null)
            jwtClaimsBuilder = jwtClaimsBuilder.claim("directory", user.getIdDir());

        String token = jwtClaimsBuilder.claim("user", user.getName())
                .claim(Claims.birthdate.name(), "2001-07-13")
                .sign();

        HashMap<String, Object> result = new HashMap<String, Object>();
        result.put("token", token);
        result.put("user", user.getName());
        result.put("user_nicename", user.getName());
        if (user.getIdDir() != null)
            result.put("directory", user.getIdDir().toString());
        List<Integer> roles = em.createQuery("SELECT ur.role.rid FROM UserRole ur WHERE ur.pk.uid=:uid",Integer.class)
                .setParameter("uid", user.getUid())
                .getResultList();
        roles.add(0);
        result.put("perms", em.createQuery("SELECT p.perm FROM Permission p WHERE p.role.rid IN :rid", String.class)
                .setParameter("rid", roles)
                .getResultList().stream()
                .flatMap(permission -> Arrays.stream(permission.split(",")))
                .collect(Collectors.toList()));
        return result;
    }

    public Object getTokenByCode(String code) {
        System.out.println("code="+code);
        try{
            Object[] row = (Object[]) em.createNativeQuery("SELECT client_id,user_id FROM oauth2_code WHERE code=:code")
                    .setParameter("code", code).setMaxResults(1).getSingleResult();
            Integer uid = Integer.parseInt(row[1].toString());
            User user = em.find(User.class, uid);
System.out.println(user);
            return getJWTInfoByUser(user);
        }catch(Exception ex){
            
            HashMap<String,Object> map=new HashMap<String,Object>();
            if(ex instanceof javax.persistence.NoResultException){
                map.put("msg", "No Found");
            }else{
                ex.printStackTrace();
                map.put("msg", ex.toString());
            }
            return map;
        }
    }

}
