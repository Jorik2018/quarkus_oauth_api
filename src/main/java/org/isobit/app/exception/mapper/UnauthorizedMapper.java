package org.isobit.app.exception.mapper;

import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

@Provider
public class UnauthorizedMapper extends BaseMapper<NotAuthorizedException> {

    @Override
    public Response toResponse(NotAuthorizedException ex) {
        return build(ex.getMessage(), Response.Status.UNAUTHORIZED);
    }
}