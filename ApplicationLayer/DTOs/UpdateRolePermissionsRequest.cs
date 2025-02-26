using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdateRolePermissionsRequest
    {
        public Guid RoleId { get; set; }
        public List<string> Permissions { get; set; }
    }
}