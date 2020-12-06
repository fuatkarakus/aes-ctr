package org.yeditepe.security.cache;

public class CacheObject {
    private Object value;
    private long expiryTime;

    public CacheObject(Object value, long expiryTime) {
        this.value = value;
        this.expiryTime = expiryTime;
    }

    public Object getValue() {
        return value;
    }

    boolean isExpired() {
        return System.currentTimeMillis() > expiryTime;
    }

}
