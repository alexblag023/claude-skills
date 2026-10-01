import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class FmtA {
    @RequestMapping("/fmt")
    @ResponseBody
    public String fmt(@RequestParam String name) {
        String f = "User " + name + " logged: %s";
        return String.format(f, "x");
    }
}
