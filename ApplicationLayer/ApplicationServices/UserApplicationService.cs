using Application.DTOs;
using Domain.Entities;
using Domain.Repositories;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class UserApplicationService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITenantRepository _tenantRepository;

        public UserApplicationService(IUserRepository userRepository, ITenantRepository tenantRepository)
        {
            _userRepository = userRepository;
            _tenantRepository = tenantRepository;
        }

        public async Task RegisterUser(RegisterUserRequest request)
        {
            var email = new Email(request.Email);
            var user = new User(request.Username, email, new byte[0], new byte[0]); // Add proper password hashing

            await _userRepository.AddAsync(user);

            foreach (var tenantId in request.TenantIds)
            {
                var tenant = await _tenantRepository.GetByIdAsync(tenantId);
                user.AddTenant(tenant, request.Role); // Correct method call
            }
            await _userRepository.UpdateAsync(user);
        }

        public async Task AddUserToTenant(AddUserToTenantRequest request)
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            var tenant = await _tenantRepository.GetByIdAsync(request.TenantId);
            user.AddTenant(tenant, request.Role); // Correct method call

            await _userRepository.UpdateAsync(user);
        }

        public async Task RemoveUserFromTenant(RemoveUserFromTenantRequest request)
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            var tenant = await _tenantRepository.GetByIdAsync(request.TenantId);
            user.RemoveTenant(tenant); // Correct method call

            await _userRepository.UpdateAsync(user);
        }
    }
}