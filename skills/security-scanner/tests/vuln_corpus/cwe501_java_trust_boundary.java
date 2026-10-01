import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class TrustA {
    @RequestMapping("/role")
    public String role(@RequestParam String role, HttpSession session) {
        session.setAttribute("role", role);
        return "ok";
    }
}
