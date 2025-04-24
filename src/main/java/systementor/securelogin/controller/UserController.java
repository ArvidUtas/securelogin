package systementor.securelogin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import systementor.securelogin.model.UserModel;
import systementor.securelogin.service.UserService;

import java.util.regex.Pattern;


@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/login")
    public String loadForm(Model model) {
        model.addAttribute("user", new UserModel());
        return "login";
    }

    @GetMapping("/register")
    public String loadRegisterForm(Model model) {
        model.addAttribute("user", new UserModel());
        return "register";
    }

    @PostMapping("/register")
    public String handleRegister(@RequestParam String username,
                                 @RequestParam String password,
                                 Model model) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!\"€/*@#$%^&-+=()])(?=\\S+$).{8,20}$";

        if (username.isEmpty() || password.isEmpty()){
            model.addAttribute("error", "Användarnamnet eller lösenordet är tomt.");
            return "register";
        }
        if (username.length() > 20){
            model.addAttribute("error", "Användarnamnet är för långt.");
            return "register";
        }
        if (userService.userIsRegistered(username)){
            model.addAttribute("error", "Användarnamnet är upptaget");
            return "register";
        }
        if (!Pattern.matches(regex, password)) {
            model.addAttribute("error", "Lösenordet måste vara mellan 8-20 tecken långt, "
            + "innehålla minst en siffra, ett liten bokstav, en stort bokstav och ett specialtecken. Mellanslag är ej tillåtna.");
            return "register";
        }
        userService.registerUser(username.trim(),password);

        return "redirect:/login";
    }


    @PostMapping("/login")
    public String handleLogin(@RequestParam String username,
                              @RequestParam String password,
                              Model model) {
        return userService.findByUsername(username)
                .filter(hashed -> new BCryptPasswordEncoder().matches(password, hashed))
                .map(found -> {
                    model.addAttribute("username", username);
                    return "welcome";
                })
                .orElseGet(() -> {
                    UserModel failedUser = new UserModel();
                    failedUser.setUsername(username);
                    model.addAttribute("user", failedUser);
                    model.addAttribute("error", "Fel användarnamn eller lösenord.");
                    return "login";
                });
    }

    @GetMapping("/update")
    public String loadUpdateForm(Model model) {
        model.addAttribute("user", new UserModel());
        return "update";
    }

    @PostMapping("/update")
    public String handleUpdate(@RequestParam String username,
                               @RequestParam String password,
                               @RequestParam String newPassword,
                               Model model) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!\"€/*@#$%^&-+=()])(?=\\S+$).{8,20}$";

        if (username.isEmpty() || password.isEmpty() || newPassword.isEmpty()){
            model.addAttribute("error", "Användarnamnet eller lösenordet är tomt.");
            return "update";
        }
        if (!userService.userIsRegistered(username)){
            model.addAttribute("error", "Kontot finns inte.");
            return "update";
        }
        if (password.equals(newPassword)){
            model.addAttribute("error", "Det nya lösenordet får inte vara samma som det gamla.");
            return "update";
        }
        if (!Pattern.matches(regex, newPassword)) {
            model.addAttribute("error", "Lösenordet måste vara mellan 8-20 tecken långt, "
                    + "innehålla minst en siffra, ett liten bokstav, en stort bokstav och ett specialtecken. Mellanslag är ej tillåtna.");
            return "update";
        }
        return userService.findByUsername(username)
                .filter(hashed -> new BCryptPasswordEncoder().matches(password, hashed))
                .map(found -> {
                    userService.updatePassword(username.trim(), password, newPassword);
                    return "redirect:/login";
                })
                .orElseGet(() -> {
                    model.addAttribute("error", "Fel användarnamn eller lösenord.");
                    return "update";
                });
    }
}
