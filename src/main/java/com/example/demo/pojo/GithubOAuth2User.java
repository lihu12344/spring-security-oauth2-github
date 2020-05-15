package com.example.demo.pojo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class GithubOAuth2User implements OAuth2User {

    private String id;
    private String login;
    private String email;

    private List<GrantedAuthority> authorities= AuthorityUtils.createAuthorityList("ROLE_USER");
    private Map<String,Object> attributes;

    @Override
    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        if (attributes==null){
            attributes=new HashMap<>();

            attributes.put("id",this.getId());
            attributes.put("name",this.getName());
            attributes.put("login",this.getLogin());
            attributes.put("email",this.getEmail());
        }

        return attributes;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getName() {
        return this.id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GithubOAuth2User)) return false;
        GithubOAuth2User that = (GithubOAuth2User) o;
        return Objects.equals(getId(), that.getId()) &&
                Objects.equals(getName(), that.getName()) &&
                Objects.equals(getLogin(), that.getLogin()) &&
                Objects.equals(getEmail(), that.getEmail()) &&
                Objects.equals(getAuthorities(), that.getAuthorities()) &&
                Objects.equals(getAttributes(), that.getAttributes());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), getName(), getLogin(), getEmail(), getAuthorities(), getAttributes());
    }

    @Override
    public String toString() {
        return "GithubOAuth2User{" +
                "id='" + id + '\'' +
                ", login='" + login + '\'' +
                ", email='" + email + '\'' +
                ", authorities=" + authorities +
                ", attributes=" + attributes +
                '}';
    }
}
