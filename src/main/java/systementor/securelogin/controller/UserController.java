package systementor.securelogin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import systementor.securelogin.model.UserModel;
import systementor.securelogin.service.LoginAttemptService;
import systementor.securelogin.service.UserService;

@Controller
public class UserController {
    @Autowired
    private LoginAttemptService loginAttemptService;

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
        String errormessage = "";

        if (username.isEmpty() || password.isEmpty()){
            errormessage = "Användarnamnet eller lösenordet är tomt.";
        } else if (!userService.isValidUsername(username)){
            errormessage = "Användarnamnet är för långt eller innehåller felaktiga karaktärer.";
        } else if (userService.userIsRegistered(username)){
            errormessage = "Användarnamnet är upptaget";
        } else if (!userService.isValidPassword(password)) {
            errormessage = "Lösenordet måste vara mellan 8-20 tecken långt, innehålla minst en siffra, "
            + "en liten bokstav, en stort bokstav och ett specialtecken. Mellanslag är ej tillåtna.";
        }

        if (!errormessage.isEmpty()) {
            model.addAttribute("error", errormessage);
            return "register";
        }
        userService.registerUser(username.trim(),password);

        return "redirect:/login";
    }


    @PostMapping("/login")
    public String handleLogin(@RequestParam String username,
                              @RequestParam String password,
                              Model model) {

        UserModel failedUser = new UserModel();
        failedUser.setUsername(username);
        if (loginAttemptService.isBlocked(username)) {
            model.addAttribute("user", failedUser);
            model.addAttribute("error", "Kontot är tillfälligt låst. Vänligen försök igen senare.");
            return "login";
        }

        return userService.findByUsername(username)
                .filter(hashed -> new BCryptPasswordEncoder().matches(password, hashed))
                .map(found -> {
                    loginAttemptService.loginSuccess(username);
                    model.addAttribute("username", username);
                    return "welcome";
                })
                .orElseGet(() -> {
                    loginAttemptService.loginFailed(username);
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
        String errormessage = "";

        if (username.isEmpty() || password.isEmpty() || newPassword.isEmpty()){
            errormessage = "Användarnamnet eller lösenordet är tomt.";
        } else if (!userService.userIsRegistered(username)){
            errormessage = "Kontot finns inte.";
        } else if (password.equals(newPassword)){
            errormessage = "Det nya lösenordet får inte vara samma som det gamla.";
        } else if (!userService.isValidPassword(newPassword)) {
            errormessage = "Lösenordet måste vara mellan 8-20 tecken långt, innehålla minst en siffra, "
                    + "en liten bokstav, en stort bokstav och ett specialtecken. Mellanslag är ej tillåtna.";
        }
        if (!errormessage.isEmpty()){
            model.addAttribute("error", errormessage);
            return "update";
        }

        return userService.findByUsername(username)
                .filter(hashed -> new BCryptPasswordEncoder().matches(password, hashed))
                .map(found -> {
                    userService.updatePassword(username.trim(), newPassword);
                    return "redirect:/login";
                })
                .orElseGet(() -> {
                    model.addAttribute("error", "Fel användarnamn eller lösenord.");
                    return "update";
                });
    }
}
