package com.auth0.samples.authapi.springbootauthupdated.security;

public class SecurityConstants {
	public static final String SECRET = "SecretKeyToGenJWTs"; // TODO: Security key
	public static final long EXPIRATION_TIME = 3600 * 1000; // 1 hour
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
	public static final String SIGN_UP_URL = "/users/sign-up"; // TODO: public route
}