using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class MfaService
    {
        private readonly Dictionary<string, string> _mfaCodes = new Dictionary<string, string>();

        public async Task SendMfaCode(User user)
        {
            var code = GenerateMfaCode();
            _mfaCodes[user.Username] = code;
            // Send the code via email or SMS
        }

        public bool VerifyMfaCode(User user, string code)
        {
            return _mfaCodes.ContainsKey(user.Username) && _mfaCodes[user.Username] == code;
        }

        private string GenerateMfaCode()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }
    }
}