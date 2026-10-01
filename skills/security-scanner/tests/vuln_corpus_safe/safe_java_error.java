import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class ErrB {
    private static final Logger logger = LoggerFactory.getLogger(ErrB.class);
    public void run() {
        try {
            Integer.parseInt("x");
        } catch (Exception e) {
            logger.error("parse failed");
        }
    }
}
