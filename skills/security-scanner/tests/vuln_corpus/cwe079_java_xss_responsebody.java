import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class XssA {
    @RequestMapping("/x")
    @ResponseBody
    public String x(@RequestParam String q) {
        return "<p>" + q + "</p>";
    }
}
