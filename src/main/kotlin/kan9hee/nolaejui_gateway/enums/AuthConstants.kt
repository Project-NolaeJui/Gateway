package kan9hee.nolaejui_gateway.enums

enum class AuthConstants(val value:String) {
    USER_ID_HEADER("X-User-Id"),
    REDIS_BLACKLIST_KEY("blacklistToken"),
    AUTHORIZATION_HEADER("Authorization"),
    BEARER_PREFIX("Bearer "),

    BEARER_SUBSTRING_START("7")
}