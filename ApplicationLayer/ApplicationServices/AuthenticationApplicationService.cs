using Infrastructure.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class AuthenticationApplicationService
    {
        private readonly AuthenticationService _authenticationService;
        private readonly JwtTokenService _jwtTokenService;
        private readonly MfaService _mfaService;

        public AuthenticationApplicationService(AuthenticationService authenticationService, JwtTokenService jwtTokenService, MfaService mfaService)
        {
            _authenticationService = authenticationService;
            _jwtTokenService = jwtTokenService;
            _mfaService = mfaService;
        }

        public async Task<string> Login(string username, string password)
        {
            var user = await _authenticationService.Authenticate(username, password);
            if (user == null)
               throw  new Exception("Invalid username or password.");

            if (user.IsMfaEnabled)
            {
                await _mfaService.SendMfaCode(user);
                throw new InvalidOperationException("MFA code required.");
            }

            return _jwtTokenService.GenerateToken(user);
        }

        public async Task<string> VerifyMfa(string username, string mfaCode)
        {
            var user = await _authenticationService.GetUserByUsername(username);
            if (user == null || !_mfaService.VerifyMfaCode(user, mfaCode))
                throw new UnauthorizedAccessException("Invalid MFA code.");

            return _jwtTokenService.GenerateToken(user);
        }

        public async Task<string> Register(string username, string email, string password)
        {
            var user = await _authenticationService.Register(username, email, password);
            return _jwtTokenService.GenerateToken(user);
        }

        public async Task RevokeToken(string token)
        {
            await _jwtTokenService.RevokeToken(token);
        }

        public async Task<string> RefreshToken(string token)
        {
            return await _jwtTokenService.RefreshToken(token);
        }
    }
}