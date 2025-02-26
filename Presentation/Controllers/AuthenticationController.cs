using Application.ApplicationServices;
using Application.DTOs;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using LoginRequest = Application.DTOs.LoginRequest;
using RegisterRequest = Application.DTOs.RegisterRequest;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly AuthenticationApplicationService _authenticationService;

        public AuthenticationController(AuthenticationApplicationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var token = await _authenticationService.Login(request.Username, request.Password);
                return Ok(new { Token = token });
            }
            catch (InvalidOperationException ex) when (ex.Message == "MFA code required.")
            {
                return Ok(new { Message = "MFA code required." });
            }
        }

        [HttpPost("verify-mfa")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaRequest request)
        {
            var token = await _authenticationService.VerifyMfa(request.Username, request.MfaCode);
            return Ok(new { Token = token });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var token = await _authenticationService.Register(request.Username, request.Email, request.Password);
            return Ok(new { Token = token });
        }

        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
        {
            await _authenticationService.RevokeToken(request.Token);
            return Ok();
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var token = await _authenticationService.RefreshToken(request.Token);
            return Ok(new { Token = token });
        }
    }
}