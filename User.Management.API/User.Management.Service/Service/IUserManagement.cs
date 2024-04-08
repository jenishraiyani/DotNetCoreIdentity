using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models;
using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models.User;

namespace User.Management.Service.Service
{
    public interface IUserManagement
    { 
         Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
         Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> role, IdentityUser user);
    }
}
