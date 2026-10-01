import java.util.Random;
public class RndA {
    public String token() {
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }
}
