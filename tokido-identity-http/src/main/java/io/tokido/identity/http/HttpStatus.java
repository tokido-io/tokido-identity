package io.tokido.identity.http;

/** The HTTP status codes the protocol layer emits in v0.1. */
public enum HttpStatus {
    OK(200), NOT_FOUND(404), NOT_IMPLEMENTED(501);

    private final int code;

    HttpStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }
}
