using SharedDomain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class Role : BaseEntity
    {
        public string Name { get; private set; }
        public List<string> Permissions { get; private set; }

        public List<UserRole> UserRoles { get; private set; } = new List<UserRole>();


        public Role(string name, List<string> permissions)
        {
            Name = name;
            Permissions = permissions;
        }

        public void UpdatePermissions(List<string> permissions)
        {
            Permissions = permissions;
        }
    }
}