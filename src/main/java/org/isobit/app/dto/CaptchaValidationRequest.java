package org.isobit.app.dto;

public class CaptchaValidationRequest {

    public String captchaId;
    public String captcha;

    public CaptchaValidationRequest() {
    }

    public CaptchaValidationRequest(
        String captchaId,
        String captcha
    ) {
        this.captchaId = captchaId;
        this.captcha = captcha;
    }
}