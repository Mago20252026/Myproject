using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class VerifyMfaRequest
    {
        public string Username { get; set; }
        public string MfaCode { get; set; }
    }
}