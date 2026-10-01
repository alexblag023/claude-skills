import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@Controller
public class LogA {
    private static final Logger logger = LoggerFactory.getLogger(LogA.class);
    @RequestMapping("/l")
    public String l(@RequestParam String user) {
        logger.info("login by " + user);
        return "ok";
    }
}
