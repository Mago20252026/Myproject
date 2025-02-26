using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class CreateRoleRequest
    {
        public string TenantId { get; set; }
        public string RoleName { get; set; }
        public List<string> Permissions { get; set; }
    }
}