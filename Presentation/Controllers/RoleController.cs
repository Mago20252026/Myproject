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
    public class RoleController : ControllerBase
    {
        private readonly RoleApplicationService _roleApplicationService;

        public RoleController(RoleApplicationService roleApplicationService)
        {
            _roleApplicationService = roleApplicationService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromBody] CreateRoleRequest request)
        {
            await _roleApplicationService.CreateRole(request.TenantId, request.RoleName, request.Permissions);
            return Ok();
        }

        [HttpPut("update")]
        public async Task<IActionResult> Update([FromBody] UpdateRolePermissionsRequest request)
        {
            await _roleApplicationService.UpdateRolePermissions(request.RoleId, request.Permissions);
            return Ok();
        }

        [HttpDelete("delete")]
        public async Task<IActionResult> Delete([FromBody] DeleteRoleRequest request)
        {
            await _roleApplicationService.DeleteRole(request.RoleId);
            return Ok();
        }
    }
}