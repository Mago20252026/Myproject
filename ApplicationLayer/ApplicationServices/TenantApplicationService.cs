using Application.DTOs;
using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class TenantApplicationService
    {
        private readonly ITenantRepository _tenantRepository;

        public TenantApplicationService(ITenantRepository tenantRepository)
        {
            _tenantRepository=tenantRepository;
        }

        public async Task CreateTenant(CreateTenantRequest request) 
        {
            var tenant = new Tenant(request.Name);
            await _tenantRepository.AddAsync(tenant);
        }

        public async Task UpdateTenant(UpdateTenantRequest request)
        {
            var tenant = await _tenantRepository.GetByIdAsync(request.TenantId);
            tenant.UpdateName(request.Name);
            await _tenantRepository.UpdateAsync(tenant);
        }

        public async Task DeleteTenant(DeleteTenantRequest request) 
        {
            await _tenantRepository.DeleteAsync(request.TenantId);
        }
    }
}
