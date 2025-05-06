package kan9hee.nolaejui_gateway.enums

enum class JwtWhitelistPath(val path:String) {
    LOG_IN("/auth/logIn"),
    SIGN_UP("/auth/signUp"),
    REISSUE_ACCESS_TOKEN("/auth/reissueAccessToken");

    companion object{
        fun allPaths(): List<String> = entries.map { it.path }
    }
}