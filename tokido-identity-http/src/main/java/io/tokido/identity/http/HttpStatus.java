package io.tokido.identity.http;

/** The HTTP status codes the protocol layer emits. */
public enum HttpStatus {
    OK(200), BAD_REQUEST(400), UNAUTHORIZED(401), NOT_FOUND(404),
    METHOD_NOT_ALLOWED(405), NOT_IMPLEMENTED(501), SERVER_ERROR(500);

    private final int code;

    HttpStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }
}
