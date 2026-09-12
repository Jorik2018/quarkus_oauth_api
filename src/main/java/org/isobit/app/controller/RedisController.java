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
public class RedisResource {

    private final KeyCommands<String> keys;
    private final ValueCommands<String, String> values;

    @Inject
    public RedisResource(RedisDataSource redisDataSource) {
        this.keys = redisDataSource.key();
        this.values = redisDataSource.value(String.class);
    }

    @GET
    @Path("/keys")
    public List<String> getKeys() {
        return keys.keys("*");
    }

    @POST
    @Path("/keys")
    public Response create(KeyRequest request) {

        if (request == null ||
                request.key == null ||
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

        values.set(
                request.key,
                request.value
        );

        return Response.status(Response.Status.CREATED)
                .entity(Map.of(
                        "key", request.key,
                        "value", request.value
                ))
                .build();
    }

    public static class KeyRequest {

        public String key;
        public String value;

    }
}