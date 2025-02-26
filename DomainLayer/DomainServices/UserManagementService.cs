using Domain.Entities;
using Domain.Repositories;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainServices
{
    public class UserManagementService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITenantRepository _tenantRepository;

        public UserManagementService(IUserRepository userRepository, ITenantRepository tenantRepository)
        {
            _userRepository = userRepository;
            _tenantRepository = tenantRepository;
        }

        public async Task RegisterUserAsync(User user)
        {
            await _userRepository.AddAsync(user);
        }

        public async Task AddUserToTenantAsync(User user, Tenant tenant, TenantRole role)
        {
            user.AddTenant(tenant, role);
            await _userRepository.UpdateAsync(user);
        }

        public async Task RemoveUserFromTenantAsync(User user, Tenant tenant)
        {
            user.RemoveTenant(tenant);
            await _userRepository.UpdateAsync(user);
        }
    }
}