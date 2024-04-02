using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.Login;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Service;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
         
        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists!" });
            }
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName
            };

            if(await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                         new Response { Status = "Error", Message = "User Failed to Create." });
                }
                await _userManager.AddToRoleAsync(user,role);

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink  = Url.Action(nameof(ConfirmEmail),"Authentication",new {token, email = user.Email});
                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                      new Response { Status = "Success", Message = $"User Created & Email Sent to {user.Email} Successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "This role Doesnot Exist." });
            }
            
        }


        //[HttpGet]
        //public IActionResult TestEmail()
        //{
        //    var message =
        //        new Message(new string[] { "jenishraiyani74@gmail.com" }, "Test", "<h1>Subscribe to my channel</h1>");
        //    _emailService.SendEmail(message);
        //    return StatusCode(StatusCodes.Status403Forbidden,
        //         new Response { Status = "Error", Message = "User already exists!" });
        //}

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token); 
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                   new Response { Status = "Success", Message = "Email Verified Successfully." });
                }   
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                   new Response { Status = "Error", Message = "User Does Not exist!" });

        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user,loginModel.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach(var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role,role));
                }
                var jwtToken = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
            }
            return Unauthorized();

        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(

                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims : authClaims,
                signingCredentials : new SigningCredentials(authSigningKey,SecurityAlgorithms.HmacSha256)
                );
            return token;

        }

    }
}
