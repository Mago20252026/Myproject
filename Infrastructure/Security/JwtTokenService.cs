using Domain.Entities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class JwtTokenService
    {
        private readonly string _secret;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly Dictionary<string, string> _refreshTokens = new Dictionary<string, string>();

        public JwtTokenService(string secret, string issuer, string audience)
        {
            _secret = secret;
            _issuer = issuer;
            _audience = audience;
        }

        public string GenerateToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(JwtRegisteredClaimNames.Email, user.Email.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30), // Token expiration time
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task RevokeToken(string token)
        {
            _refreshTokens.Remove(token);
        }

        public async Task<string> RefreshToken(string token)
        {
            if (_refreshTokens.ContainsKey(token))
            {
                var userId = _refreshTokens[token];
                var user = await GetUserById(Guid.Parse(userId));
                return GenerateToken(user);
            }

            throw new SecurityTokenException("Invalid token.");
        }

        private async Task<User> GetUserById(Guid userId)
        {
            // Fetch the user from the database or repository
            return new User(); // Placeholder
        }
    }
}