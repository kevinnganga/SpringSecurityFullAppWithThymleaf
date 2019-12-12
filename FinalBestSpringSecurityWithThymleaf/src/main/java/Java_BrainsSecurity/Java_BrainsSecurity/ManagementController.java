package Java_BrainsSecurity.Java_BrainsSecurity;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("management")
public class ManagementController {

    @GetMapping("index")
    public String index(){
        return "management/index";
    }
}
