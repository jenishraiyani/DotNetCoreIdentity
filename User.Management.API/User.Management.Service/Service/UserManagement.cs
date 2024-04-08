using System.Data;
using System;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using User.Management.Service.Models.User;

namespace User.Management.Service.Service
{
    public class UserManagement : IUserManagement
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        

        public UserManagement(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, 
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }
        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = StatusCodes.Status403Forbidden,
                    Message = "User already exists!"
                };
                
            }
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true
            };
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse>
                {
                    Response = new CreateUserResponse() {User= user,Token= token },
                    IsSuccess = true,
                    StatusCode = StatusCodes.Status200OK,
                    Message = "User Created."
                };
            }
            else
            {
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Message = "User Failed to Create."
                };
            }
        }
        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> role, IdentityUser user)
        {
            var assignedRole = new List<string>();
            foreach(var roleItem in role)
            {
                if(await _roleManager.RoleExistsAsync(roleItem))
                {
                    if(!await _userManager.IsInRoleAsync(user, roleItem))
                    {
                        await _userManager.AddToRoleAsync(user, roleItem);
                        assignedRole.Add(roleItem);
                    }
                }
            }
            return new ApiResponse<List<string>>
            {
                IsSuccess = true,
                StatusCode = StatusCodes.Status200OK,
                Message = "Roles has been assigned",
                Response = assignedRole
            };
        }
    }
}
