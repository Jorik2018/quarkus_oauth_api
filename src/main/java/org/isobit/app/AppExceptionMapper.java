package org.isobit.app;

import java.util.HashMap;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

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
