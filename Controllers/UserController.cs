using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ConexionEF.Models;
using System.Linq;
using System.Threading.Tasks;
using ConexionEF.Services;

namespace ConexionEF.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ApplicationDbContext _context;

        public UserController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _context = context;
        }

        // Método para inicializar roles si no existen
        public async Task<IActionResult> InitializeRoles()
        {
            string[] roleNames = { MyConstants.RolAdmin, MyConstants.RolVendedor };

            foreach (var roleName in roleNames)
            {
                if (!await _roleManager.RoleExistsAsync(roleName))
                {
                    await _roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            return RedirectToAction("Index", "Home");
        }

        [AllowAnonymous]
        public IActionResult Registry()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Registry(RegistryViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = new IdentityUser()
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, MyConstants.RolVendedor); // Asignar rol de vendedor por defecto al registrar

                // Ejemplo de cómo agregar un claim al usuario
               

                await _signInManager.SignInAsync(user, isPersistent: true); // Iniciar sesión después del registro

                return RedirectToAction("Index", "Home");
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return View(model);
            }
        }

        [AllowAnonymous]
        public IActionResult Login(string message = null)
        {
            ViewData["Message"] = message;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.Remember, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Nombre de usuario o contraseña incorrectos");
                return View(model);
            }
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> List(string confirmed = null, string remove = null)
{
    var userList = await _context.Users.ToListAsync();
    var userRoleList = await _context.UserRoles.ToListAsync();

    var model = new UserListViewModel();

    var userDtoList = userList.Select(u => new UserViewModel
    {
        User = u.UserName,
        Email = u.Email,
        Confirmed = u.EmailConfirmed,
        IsAdmin = userRoleList.Any(ur => ur.UserId == u.Id &&_roleManager.Roles.Any(r => r.Id == ur.RoleId && r.Name == MyConstants.RolAdmin)),
        IsVendedor = userRoleList.Any(ur => ur.UserId == u.Id && _roleManager.Roles.Any(r => r.Id == ur.RoleId && r.Name == MyConstants.RolVendedor))
    })
    .OrderBy(u => u.User)
    .ToList();

    model.UserList = userDtoList;
    model.MessageConfirmed = confirmed;
    model.MessageRemoved = remove;

    return View(model);
}

        [HttpPost]
        [Authorize(Roles = MyConstants.RolAdmin)]
        public async Task<IActionResult> HacerAdmin(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            await _userManager.AddToRoleAsync(user, MyConstants.RolAdmin);

            return RedirectToAction("List", new { confirmed = $"Rol de administrador asignado correctamente a {email}", remove = "" });
        }

        

        [HttpPost]
        [Authorize(Roles = MyConstants.RolAdmin)]
        public async Task<IActionResult> RemoverAdmin(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            await _userManager.RemoveFromRoleAsync(user, MyConstants.RolAdmin);

            return RedirectToAction("List", new { confirmed = "", remove = $"Rol de administrador removido correctamente a {email}" });
        }

        [HttpPost]
        [Authorize(Roles = MyConstants.RolAdmin)]
        public async Task<IActionResult> HacerVendedor(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            await _userManager.AddToRoleAsync(user, MyConstants.RolVendedor);

            return RedirectToAction("List", new { confirmed = $"Rol de vendedor asignado correctamente a {email}", remove = "" });
        }

        [HttpPost]
        [Authorize(Roles = MyConstants.RolAdmin)]
        public async Task<IActionResult> RemoverVendedor(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            await _userManager.RemoveFromRoleAsync(user, MyConstants.RolVendedor);

            return RedirectToAction("List", new { confirmed = "", remove = $"Rol de vendedor removido correctamente a {email}" });
        }
    }
}
