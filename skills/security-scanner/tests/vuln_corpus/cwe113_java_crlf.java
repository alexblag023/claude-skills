import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class HdrA {
    @RequestMapping("/h")
    public void h(@RequestParam String v, HttpServletResponse resp) {
        resp.addHeader("X-Custom", v);
    }
}
