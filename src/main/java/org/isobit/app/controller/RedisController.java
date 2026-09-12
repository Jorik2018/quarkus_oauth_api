package org.isobit.app.rest;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;

@Path("/redis")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RedisController {

    private final KeyCommands<String> keys;
    private final ValueCommands<String, String> values;

    @Inject
    public RedisController(RedisDataSource redisDataSource) {
        this.keys = redisDataSource.key();
        this.values = redisDataSource.value(String.class);
    }

    @GET
    @Path("/keys")
    public List<String> getKeys() {
        return keys.keys("*");
    }

    @GET
    @Path("/keys/{key}")
    public Response get(
            @PathParam("key") String key
    ) {

        String value = values.get(key);

        if (value == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of(
                            "message", "Key no encontrada",
                            "key", key
                    ))
                    .build();
        }

        long ttl = keys.ttl(key);

        return Response.ok(
                Map.of(
                        "key", key,
                        "value", value,
                        "ttl", ttl
                )
        ).build();
    }

    @POST
    @Path("/keys")
    public Response create(KeyRequest request) {

        Response validation = validate(request);

        if (validation != null) {
            return validation;
        }

        values.set(
                request.key,
                request.value
        );

        applyTtl(
                request.key,
                request.ttl
        );

        return Response.status(Response.Status.CREATED)
                .entity(Map.of(
                        "key", request.key,
                        "value", request.value,
                        "ttl", request.ttl != null
                                ? request.ttl
                                : 0
                ))
                .build();
    }

    @PUT
    @Path("/keys/{key}")
    public Response update(
            @PathParam("key") String key,
            KeyRequest request
    ) {

        if (request == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "message", "Body obligatorio"
                    ))
                    .build();
        }

        if (request.value == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "message", "value es obligatorio"
                    ))
                    .build();
        }

        boolean exists = keys.exists(key);

        values.set(
                key,
                request.value
        );

        applyTtl(
                key,
                request.ttl
        );

        return Response.ok(
                Map.of(
                        "key", key,
                        "value", request.value,
                        "ttl", request.ttl != null
                                ? request.ttl
                                : 0,
                        "created", !exists
                )
        ).build();
    }

    @DELETE
    @Path("/keys/{key}")
    public Response delete(
            @PathParam("key") String key
    ) {

        long deleted = keys.del(key);

        if (deleted == 0) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of(
                            "message", "Key no encontrada",
                            "key", key
                    ))
                    .build();
        }

        return Response.ok(
                Map.of(
                        "deleted", true,
                        "key", key
                )
        ).build();
    }

    private void applyTtl(
            String key,
            Long ttl
    ) {

        if (ttl == null || ttl <= 0) {

            /*
             * Sin expiración.
             *
             * Importante:
             * SET elimina el TTL anterior,
             * así que no necesitamos hacer persist()
             * después del set.
             */
            return;
        }

        keys.expire(
                key,
                ttl
        );
    }

    private Response validate(
            KeyRequest request
    ) {

        if (request == null) {

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "message", "Body obligatorio"
                    ))
                    .build();
        }

        if (request.key == null ||
                request.key.isBlank()) {

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "message", "key es obligatorio"
                    ))
                    .build();
        }

        if (request.value == null) {

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "message", "value es obligatorio"
                    ))
                    .build();
        }

        if (request.ttl != null &&
                request.ttl < 0) {

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "message", "ttl no puede ser negativo"
                    ))
                    .build();
        }

        return null;
    }

    public static class KeyRequest {

        public String key;

        public String value;

        /**
         * TTL en segundos.
         *
         * null o 0 = sin expiración
         * > 0       = expira después de N segundos
         */
        public Long ttl;
    }
}