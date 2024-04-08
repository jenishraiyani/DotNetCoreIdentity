using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Service;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;
         
        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IConfiguration configuration, 
            SignInManager<IdentityUser> signInManager,
            IEmailService emailService,
            IUserManagement user)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _signInManager= signInManager;
            _user = user;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response, email = registerUser.Email });
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email Verified Successfully." });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                     new Response { IsSuccess = tokenResponse.IsSuccess, Message = tokenResponse.Message });
        }
 
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
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password,false,true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
               new Response { Status = "Success", Message = $"We have sent you ans OTP to your Email {user.Email}" });

            }
            return Unauthorized();

        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code,string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if(signIn.Succeeded)
            {
                    if (user != null)
                    {
                        var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name,user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                    };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }
                    var jwtToken = GetToken(authClaims);
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                 new Response { Status = "Error", Message = "Invalid Code" });

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

        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword),"Authentication", new {token, email= user.Email},Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password link", forgotPasswordLink);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password change request sent on Email {user.Email} Successfully" });
            }
            return StatusCode(StatusCodes.Status404NotFound,
            new Response { Status = "Error", Message = $"Could not send link to email, please try again." });

        }
        [HttpGet]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(string email,string token)
        {
            var model = new ResetPassword { Token= token , Email = email};
            return Ok(new
            {
                model
            });

        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if(user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if(!resetPassResult.Succeeded)
                {
                    foreach(var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                  new Response { Status = "Success", Message = $"Password has been changed" });
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Error", Message = $"Someting went wrong" });

        }
    }
}
