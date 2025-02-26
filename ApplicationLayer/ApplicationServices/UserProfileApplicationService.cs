using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class UserProfileApplicationService
    {
        private readonly IUserRepository _userRepository;

        public UserProfileApplicationService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task UpdateUserProfile(Guid userId, string newEmail, string newUsername)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            user.UpdateEmail(newEmail);
            user.UpdateUsername(newUsername);
            await _userRepository.UpdateAsync(user);
        }

        public async Task UpdatePassword(Guid userId, string newPassword)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            byte[] passwordHash, passwordSalt;
            User.CreatePasswordHash(newPassword, out passwordHash, out passwordSalt);
            user.UpdatePassword(passwordHash, passwordSalt);
            await _userRepository.UpdateAsync(user);
        }

        public async Task EnableMfa(Guid userId, string secretKey)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            user.EnableMfa(secretKey);
            await _userRepository.UpdateAsync(user);
        }

        public async Task DisableMfa(Guid userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            user.DisableMfa();
            await _userRepository.UpdateAsync(user);
        }
    }
}