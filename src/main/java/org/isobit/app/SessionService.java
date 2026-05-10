package org.isobit.app;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.hash.HashCommands;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.time.Duration;
import java.util.Map;

@ApplicationScoped
public class SessionService {

    @Inject
    RedisDataSource redis;

    HashCommands<String, String, String> hash;

    @ConfigProperty(name = "session.redis.enabled", defaultValue = "true")
    boolean redisEnabled;

    private static final String PREFIX = "session:";

    @PostConstruct
    void init() {
        hash = redis.hash(String.class);
    }

    // 🔥 crear o actualizar campos sin pisar otros micros
    public void put(String jti, String field, String value, long ttlSeconds) {
        if (!redisEnabled) return;
        String key = PREFIX + jti;
        hash.hset(key, field, value);
        redis.key().expire(key, Duration.ofSeconds(ttlSeconds));
    }

    // 🔥 batch insert (ideal para login)
    public void putAll(String jti, Map<String, String> data, long ttlSeconds) {
        if (!redisEnabled) return;
        String key = PREFIX + jti;

        hash.hset(key, data);
        redis.key().expire(key, Duration.ofSeconds(ttlSeconds));
    }

    // 🔥 leer un campo específico
    public String get(String jti, String field) {
        if (!redisEnabled) return null;
        return hash.hget(PREFIX + jti, field);
    }

    // 🔥 obtener toda la sesión
    public Map<String, String> getAll(String jti) {
        return hash.hgetall(PREFIX + jti);
    }

    // 🔥 eliminar sesión completa
    public void delete(String jti) {
        redis.key().del(PREFIX + jti);
    }

    // 🔥 extender TTL (sliding session)
    public void refresh(String jti, long ttlSeconds) {
        if (!redisEnabled) return;
        redis.key().expire(PREFIX + jti, Duration.ofSeconds(ttlSeconds));
    }
}