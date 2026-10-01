import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class TrustB {
    @RequestMapping("/flag")
    public String flag(HttpSession session) {
        session.setAttribute("flag", "constant");
        return "ok";
    }
}
