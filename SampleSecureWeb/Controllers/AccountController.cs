using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SampleSecureWeb.Data;
using SampleSecureWeb.Models;
using SampleSecureWeb.ViewModels;
using System.Text.RegularExpressions;

namespace SampleSecureWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;

        public AccountController(IUser user)
        {
            _userData = user;
        }

        // GET: AccountController
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    // Validasi kata sandi
                    if (!IsValidPassword(registrationViewModel.Password))
                    {
                        ModelState.AddModelError("Password", "Kata sandi harus minimal 12 karakter dan mengandung setidaknya satu huruf besar, satu huruf kecil, dan satu angka.");
                        return View(registrationViewModel);
                    }

                    var user = new Models.User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        RoleName = "Contributor"
                    };
                    _userData.Registration(user);
                    ViewBag.Massage = "Pendaftaran berhasil!";
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
            }
            return View(registrationViewModel);
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");

                var user = new User
                {
                    Username = loginViewModel.Username,
                    Password = loginViewModel.Password
                };

                var loginUser = _userData.Login(user);
                if (loginUser == null)
                {
                    ViewBag.Massage = "Upaya Login Tidak Valid";
                    return View(loginViewModel);
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username)
                };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = loginViewModel.RememberLogin
                    });

                return RedirectToAction("Index", "Home");
            }
            catch (System.Exception ex)
            {
                ViewBag.Massage = ex.Message;
            }
            return View(loginViewModel);
        }

        // GET: Ubah Kata Sandi
        public ActionResult GantiPassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult GantiPassword(GantiPasswordViewModel gantiPasswordViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    if (!IsValidPassword(gantiPasswordViewModel.NewPassword))
                    {
                        ModelState.AddModelError("NewPassword", "Kata sandi harus minimal 12 karakter dan mengandung setidaknya satu huruf besar, satu huruf kecil, dan satu angka.");
                        return View(gantiPasswordViewModel);
                    }

                    var username = User.Identity?.Name;
                    if (username == null)
                    {
                        return RedirectToAction("Login");
                    }

                    var user = _userData.GetUserByUsername(username);
                    if (user == null || !BCrypt.Net.BCrypt.Verify(gantiPasswordViewModel.CurrentPassword, user.Password))
                    {
                        ModelState.AddModelError("CurrentPassword", "Kata sandi saat ini salah.");
                        return View(gantiPasswordViewModel);
                    }

                    // Mengupdate kata sandi
                    user.Password = BCrypt.Net.BCrypt.HashPassword(gantiPasswordViewModel.NewPassword);
                    _userData.UpdateUser(user);
                    ViewBag.Massage = "Kata sandi berhasil diubah!";
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
            }
            return View(gantiPasswordViewModel);
        }

        private bool IsValidPassword(string password)
        {
            return password.Length >= 12 &&
                Regex.IsMatch(password, @"[A-Z]") &&
                Regex.IsMatch(password, @"[0-9]") &&
                Regex.IsMatch(password, @"[a-z]");

        }

        public async Task<ActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index","Home");
        }
        
    }
}