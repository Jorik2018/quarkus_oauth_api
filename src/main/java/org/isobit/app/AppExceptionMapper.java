package org.isobit.app;

import java.util.HashMap;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class AppExceptionMapper implements ExceptionMapper<Throwable> {
  
	@Override
	public Response toResponse(Throwable throwable) {
		HashMap map=new HashMap();
		throwable.printStackTrace();
		map.put("msg", throwable.getMessage());
		return Response
			.status(Response.Status.INTERNAL_SERVER_ERROR)
			.entity(map)
			.build();
	}
}
