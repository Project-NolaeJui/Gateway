package kan9hee.nolaejui_gateway.config

import kan9hee.nolaejui_gateway.component.AuthorizationHeaderFilter
import kan9hee.nolaejui_gateway.component.JwtSecurityFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
@EnableWebFluxSecurity
class FilterConfig(private val headerFilter: AuthorizationHeaderFilter) {

    @Bean
    fun filterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .httpBasic{ it.disable() }
            .csrf { it.disable() }
            .authorizeExchange { authorize ->
                authorize
                    .pathMatchers("/auth/**").permitAll()
                    .anyExchange().authenticated()
            }
            .addFilterAt(JwtSecurityFilter(headerFilter), SecurityWebFiltersOrder.AUTHENTICATION)
            .build()
    }
}