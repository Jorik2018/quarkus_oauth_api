package org.isobit.app.client;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.isobit.app.dto.CaptchaValidationRequest;
import org.isobit.app.dto.CaptchaValidationResponse;

@Path("/api/capcha")
@RegisterRestClient(configKey = "captcha-api")
public interface CaptchaClient {

    @POST
    @Path("/validate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    CaptchaValidationResponse validate(
        CaptchaValidationRequest request
    );
}