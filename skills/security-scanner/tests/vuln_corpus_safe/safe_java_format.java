import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;
@Controller
public class FmtB {
    @RequestMapping("/fmt")
    @ResponseBody
    public String fmt(@RequestParam String name) {
        return String.format("User %s logged", HtmlUtils.htmlEscape(name));
    }
}
