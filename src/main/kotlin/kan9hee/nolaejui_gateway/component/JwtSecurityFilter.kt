package kan9hee.nolaejui_gateway.component

import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

@Component
class JwtSecurityFilter(private val authorizationHeaderFilter: AuthorizationHeaderFilter): WebFilter {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val request = exchange.request
        val token = authorizationHeaderFilter.extractToken(request)

        if (token != null && authorizationHeaderFilter.isJwtValid(token)) {
            val authentication = authorizationHeaderFilter.getAuthentication(token)
            ReactiveSecurityContextHolder.withAuthentication(authentication)
        }

        return chain.filter(exchange)
    }
}