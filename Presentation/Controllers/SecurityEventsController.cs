using Infrastructure.Security;
using Microsoft.AspNetCore.Mvc;
using System;
using Application.DTOs;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityEventsController : ControllerBase
    {
        private readonly SecurityService _securityService;

        public SecurityEventsController(SecurityService securityService)
        {
            _securityService = securityService;
        }

        [HttpPost("log")]
        public IActionResult LogSecurityEvent([FromBody] SecurityEventRequest request)
        {
            _securityService.LogSecurityEvent(request.EventType, request.Details);
            return Ok();
        }
    }
}