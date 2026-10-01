import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class ToolsB {
    @RequestMapping("/ping")
    public String ping(@RequestParam(value = "n") int n) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[] { "bash", "-c", "ping -c1 127.0.0.1" });
        return "ok";
    }
}
