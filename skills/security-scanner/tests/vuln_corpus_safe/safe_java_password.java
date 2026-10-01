public class CfgD {
    private final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private final String PLACEHOLDER_PASSWORD = "${DB_PASSWORD}";
    private final String EMPTY_PASSWORD = "";
    private static final String TOKEN_HEADER = "X";
    private static final String USERNAME_FIELD = "username";
}
