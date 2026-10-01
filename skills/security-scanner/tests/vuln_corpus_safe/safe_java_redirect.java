import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class RedirB {
    @RequestMapping("/go")
    public String go(@RequestParam String target) {
        return "redirect:/home";
    }
}
