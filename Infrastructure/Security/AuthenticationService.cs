using Domain.Entities;
using Domain.Repositories;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class AuthenticationService
    {
        private readonly IUserRepository _userRepository;

        public AuthenticationService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task<User> Authenticate(string username, string password)
        {
            var user = await _userRepository.GetByUsernameAsync(username);
            if (user == null || !VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                return null;

            return user;
        }

        public async Task<User> Register(string username, string email, string password)
        {
            if (await _userRepository.UserExists(username, email))
                throw new InvalidOperationException("User already exists.");

            byte[] passwordHash, passwordSalt;
            User.CreatePasswordHash(password, out passwordHash, out passwordSalt);

            var user = new User(username, new Email(email), passwordHash, passwordSalt);
            await _userRepository.AddAsync(user);

            return user;
        }

        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(storedHash);
            }
        }

        public async Task<User> GetUserByUsername(string username)
        {
            return await _userRepository.GetByUsernameAsync(username);
        }
    }
}