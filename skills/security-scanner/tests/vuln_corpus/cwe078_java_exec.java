import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
@Controller
public class ToolsA {
    @RequestMapping("/ping")
    public String ping(@RequestParam(value = "host") String host) throws Exception {
        return run(host);
    }
    private String run(String host) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[] { "bash", "-c", "ping -c1 " + host });
        return "ok";
    }
}
