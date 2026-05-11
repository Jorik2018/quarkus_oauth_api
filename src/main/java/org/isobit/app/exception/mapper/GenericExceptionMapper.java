package org.isobit.app.exception.mapper;

import java.util.HashMap;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class GenericExceptionMapper implements ExceptionMapper<Exception> {

    @Override
    public Response toResponse(Exception ex) {
        ex.printStackTrace();

        HashMap<String, Object> map = new HashMap<>();
        map.put("msg", "Error interno del servidor");

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(map)
                .build();
    }
}