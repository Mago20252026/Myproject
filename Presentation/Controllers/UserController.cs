using Application.ApplicationServices;
using Application.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserApplicationService _userApplicationService;

        public UserController(UserApplicationService userApplicationService)
        {
            _userApplicationService = userApplicationService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
        {
            await _userApplicationService.RegisterUser(request);
            return Ok();
        }

        [HttpPost("add-to-tenant")]
        public async Task<IActionResult> AddUserToTenant([FromBody] AddUserToTenantRequest request)
        {
            await _userApplicationService.AddUserToTenant(request);
            return Ok();
        }

        [HttpPost("remove-from-tenant")]
        public async Task<IActionResult> RemoveUserFromTenant([FromBody] RemoveUserFromTenantRequest request)
        {
            await _userApplicationService.RemoveUserFromTenant(request);
            return Ok();
        }
    }
}