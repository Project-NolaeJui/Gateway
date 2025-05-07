package kan9hee.nolaejui_gateway.enums

enum class JwtAdminPath(val path:String) {
    ADMIN_CHANGE_MUSIC("/management/logIn"),
    ADMIN_DELETE_MUSIC("/management/signUp"),
    ADMIN_DISABLE_LOG("/management/signUp"),
    ADMIN_DELETE_USER("/management/signUp"),
    ADMIN_CREATE_ACCOUNT("/management/reissueAccessToken");

    companion object{
        fun allPaths(): List<String> = JwtWhitelistPath.entries.map { it.path }
    }
}