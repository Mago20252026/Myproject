using Application.ApplicationServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Application.DTOs;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserProfileController : ControllerBase
    {
        private readonly UserProfileApplicationService _userProfileApplicationService;

        public UserProfileController(UserProfileApplicationService userProfileApplicationService)
        {
            _userProfileApplicationService = userProfileApplicationService;
        }

        [HttpPut("update-profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserProfileRequest request)
        {
            await _userProfileApplicationService.UpdateUserProfile(request.UserId, request.NewEmail, request.NewUsername);
            return Ok();
        }

        [HttpPut("update-password")]
        public async Task<IActionResult> UpdatePassword([FromBody] UpdatePasswordRequest request)
        {
            await _userProfileApplicationService.UpdatePassword(request.UserId, request.NewPassword);
            return Ok();
        }

        [HttpPut("enable-mfa")]
        public async Task<IActionResult> EnableMfa([FromBody] EnableMfaRequest request)
        {
            await _userProfileApplicationService.EnableMfa(request.UserId, request.SecretKey);
            return Ok();
        }

        [HttpPut("disable-mfa")]
        public async Task<IActionResult> DisableMfa([FromBody] DisableMfaRequest request)
        {
            await _userProfileApplicationService.DisableMfa(request.UserId);
            return Ok();
        }
    }
}