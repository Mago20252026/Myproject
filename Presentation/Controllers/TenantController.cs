using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Application.ApplicationServices;
using Application.DTOs;

namespace Presentation.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TenantController : ControllerBase
    {
        private readonly TenantApplicationService _tenantApplicationService;

        public TenantController(TenantApplicationService tenantApplicationService)
        {
            _tenantApplicationService = tenantApplicationService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromBody] CreateTenantRequest request)
        {
            await _tenantApplicationService.CreateTenant(request);
            return Ok();
        }

        [HttpPut("update")]
        public async Task<IActionResult> Update([FromBody] UpdateTenantRequest request)
        {
            await _tenantApplicationService.UpdateTenant(request);
            return Ok();
        }

        [HttpDelete("delete")]
        public async Task<IActionResult> Delete([FromBody] DeleteTenantRequest request)
        {
            await _tenantApplicationService.DeleteTenant(request);
            return Ok();
        }
    }
}