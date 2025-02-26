using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class RoleApplicationService
    {
        private readonly IRoleRepository _roleRepository;
        private readonly ITenantRepository _tenantRepository;

        public RoleApplicationService(IRoleRepository roleRepository, ITenantRepository tenantRepository)
        {
            _roleRepository = roleRepository;
            _tenantRepository = tenantRepository;
        }

        public async Task CreateRole(string tenantId, string roleName, List<string> permissions)
        {
            var role = new Role(roleName, permissions);
            await _roleRepository.AddAsync(role);
        }

        public async Task UpdateRolePermissions(Guid roleId, List<string> permissions)
        {
            var role = await _roleRepository.GetByIdAsync(roleId);
            role.UpdatePermissions(permissions);
            await _roleRepository.UpdateAsync(role);
        }

        public async Task DeleteRole(Guid roleId)
        {
            await _roleRepository.DeleteAsync(roleId);
        }
    }
}