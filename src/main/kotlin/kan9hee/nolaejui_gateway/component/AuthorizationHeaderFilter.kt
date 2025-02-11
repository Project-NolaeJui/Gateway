package kan9hee.nolaejui_gateway.component

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.core.env.Environment
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class AuthorizationHeaderFilter(@Value("\${jwt.secret}") secretKey: String,
                                private val env:Environment,
                                private val stringRedisTemplate: StringRedisTemplate
): AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>(Config::class.java) {

    private val key: SecretKey

    init {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        key = Keys.hmacShaKeyFor(keyBytes)
    }

    class Config

    override fun apply(config: Config): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            val request = exchange.request
            val token = extractToken(request)

            if (token == null || !isJwtValid(token)) {
                exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                return@GatewayFilter exchange.response.setComplete()
            }

            chain.filter(exchange)
        }
    }

    fun isJwtValid(token: String?): Boolean {
        return try {
            val claims: Claims = Jwts.parser()
                .verifyWith(this.key)
                .build()
                .parseSignedClaims(token)
                .payload

            val expirationDate = claims.expiration
            if (expirationDate.before(Date()) || stringRedisTemplate.hasKey("blacklistToken:$token"))
                return false

            true
        } catch (ex: Exception) {
            false
        }
    }

    fun getAuthentication(token: String): UsernamePasswordAuthenticationToken {
        val claims = Jwts.parser()
            .verifyWith(this.key)
            .build()
            .parseSignedClaims(token)
            .payload ?: throw RuntimeException("권한 정보 없음")

        val authorities = claims["auth"]
            .toString()
            .split(",")
            .map { SimpleGrantedAuthority(it) }

        val principal = User(claims.subject, "", authorities)
        return UsernamePasswordAuthenticationToken(principal, "", authorities)
    }

    fun extractToken(request: ServerHttpRequest): String? {
        val authHeader = request.headers.getFirst("Authorization") ?: return null
        return if (authHeader.startsWith("Bearer ")) authHeader.substring(7) else null
    }
}