import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
@Controller
public class ImplA {
    @RequestMapping(value = "/hint", method = RequestMethod.GET)
    @ResponseBody
    public String hint(String username) {
        String f = "Username '" + username + "' has password: %s";
        return String.format(f, "x");
    }
}
