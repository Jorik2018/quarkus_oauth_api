package org.isobit.app.exception.mapper;

import java.util.Map;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;

public abstract class BaseMapper<T extends Throwable> implements ExceptionMapper<T> {

    protected Response build(String msg, Response.Status status) {
        return Response.status(status)
                .entity(Map.of("msg", msg))
                .build();
    }
}