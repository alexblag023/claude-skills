import java.security.SecureRandom;
public class RndB {
    public String token() {
        SecureRandom r = new SecureRandom();
        return Long.toHexString(r.nextLong());
    }
}
