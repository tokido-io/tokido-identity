package io.tokido.auth.model;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.*;

@DynamoDbBean
public class AuthCode {
    private String code, sessionId, clientId, loginHint, createdAt;
    private long ttl;
    private boolean used;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("code")
    public String getCode() { return code; }
    public void setCode(String v) { this.code = v; }
    @DynamoDbAttribute("session_id")
    public String getSessionId() { return sessionId; }
    public void setSessionId(String v) { this.sessionId = v; }
    @DynamoDbSecondaryPartitionKey(indexNames = "client_id-index")
    @DynamoDbAttribute("client_id")
    public String getClientId() { return clientId; }
    public void setClientId(String v) { this.clientId = v; }
    @DynamoDbAttribute("login_hint")
    public String getLoginHint() { return loginHint; }
    public void setLoginHint(String v) { this.loginHint = v; }
    @DynamoDbAttribute("created_at")
    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String v) { this.createdAt = v; }
    @DynamoDbAttribute("ttl")
    public long getTtl() { return ttl; }
    public void setTtl(long v) { this.ttl = v; }
    @DynamoDbAttribute("used")
    public boolean isUsed() { return used; }
    public void setUsed(boolean v) { this.used = v; }
}
