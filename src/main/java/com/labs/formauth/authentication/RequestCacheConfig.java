package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
public class RequestCacheConfig {

    @Bean
    public RequestCache requestCache() {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();

        // Real production concern: an XHR/fetch call that hits a protected
        // endpoint and gets redirected should NOT be remembered as "the
        // page the user wanted" - replaying an API call as a full-page GET
        // navigation later makes no sense. saveRequest() silently no-ops
        // when this matcher returns false. There is NO such exclusion by
        // default - HttpSessionRequestCache matches everything unless told
        // otherwise, which is exactly what this bean changes.
        cache.setRequestMatcher(request ->
                !"XMLHttpRequest".equals(request.getHeader("X-Requested-With")));

        return cache;

        // CONTRAST TOGGLE: replace the block above with the single line
        // below to disable deep-link replay entirely - useful for APIs
        // where "always land on a fixed URL" is actually the desired behavior.
        // return new org.springframework.security.web.savedrequest.NullRequestCache();
    }
}