import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;
@Controller
public class XssB {
    @RequestMapping("/x")
    @ResponseBody
    public String x(@RequestParam String q) {
        return "<p>" + HtmlUtils.htmlEscape(q) + "</p>";
    }
}
