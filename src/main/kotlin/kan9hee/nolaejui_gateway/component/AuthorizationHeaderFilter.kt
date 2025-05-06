package kan9hee.nolaejui_gateway.component

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import kan9hee.nolaejui_gateway.enums.AuthConstants
import kan9hee.nolaejui_gateway.enums.JwtWhitelistPath
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import javax.crypto.SecretKey

@Component
class AuthorizationHeaderFilter(
    @Value("\${jwt.secret}") secretKey: String,
    private val stringRedisTemplate: StringRedisTemplate
): AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>(Config::class.java) {

    private val key: SecretKey

    class Config

    init {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        key = Keys.hmacShaKeyFor(keyBytes)
    }

    override fun apply(config: Config): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            val request = exchange.request
            val path = request.path.value()
            if (JwtWhitelistPath.allPaths().any { path == it }) {
                return@GatewayFilter chain.filter(exchange)
            }

            val token = extractToken(request)
            val claims = parseClaims(token)

            if (claims == null || isTokenBlacklisted(token!!)) {
                exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                return@GatewayFilter exchange.response.setComplete()
            }

            val mutatedRequest = exchange.request.mutate()
                .header(
                    AuthConstants.USER_ID_HEADER.value,
                    claims.subject
                )
                .build()
            chain.filter(exchange.mutate().request(mutatedRequest).build())
        }
    }

    private fun parseClaims(token: String?): Claims? {
        return try {
            if (token == null)
                return null
            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .payload
        } catch (ex: Exception) {
            null
        }
    }

    private fun isTokenBlacklisted(token: String): Boolean {
        return stringRedisTemplate.hasKey("${AuthConstants.REDIS_BLACKLIST_KEY.value}:$token")
    }

    fun extractToken(request: ServerHttpRequest): String? {
        val authHeader = request.headers.getFirst(AuthConstants.AUTHORIZATION_HEADER.value)
            ?: return null

        return if (authHeader.startsWith(AuthConstants.BEARER_PREFIX.value))
            authHeader.substring(AuthConstants.BEARER_SUBSTRING_START.value.toInt())
        else null
    }
}