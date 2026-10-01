import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class ReflB {
    @RequestMapping("/cmd")
    public String cmd(@RequestParam String command) throws Exception {
        Class<?> c = Class.forName("app.commands.FixedCommand");
        return c.getName();
    }
}
