package org.isobit.app.exception.mapper;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

@Provider
public class BadRequestMapper extends BaseMapper<BadRequestException> {

    @Override
    public Response toResponse(BadRequestException ex) {
        return build(ex.getMessage(), Response.Status.BAD_REQUEST);
    }
}