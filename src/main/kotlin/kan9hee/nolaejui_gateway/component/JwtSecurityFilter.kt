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

        return if (token != null && authorizationHeaderFilter.isJwtValid(token)) {
            val authentication = authorizationHeaderFilter.getAuthentication(token)
            chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
        } else {
            chain.filter(exchange)
        }
    }
}