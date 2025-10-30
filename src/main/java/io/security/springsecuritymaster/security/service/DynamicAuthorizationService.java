package io.security.springsecuritymaster.security.service;

import io.security.springsecuritymaster.security.mapper.UrlRoleMapper;

import java.util.Map;

public class DynamicAuthorizationService {

    private final UrlRoleMapper delegete;

    public DynamicAuthorizationService(UrlRoleMapper delegete) {
        this.delegete = delegete;
    }

    public Map<String, String> getRoleMappings() {
        return delegete.getUrlRoleMappings();
    }
}
