using Domain.Entities;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Aggregates
{
    public class TenantAggregate
    {
        public Tenant Tenant {  get; private set; }
        public List<User> Users { get; private set; }

        public TenantAggregate(Tenant tenant) 
        {
            Tenant = tenant;
            Users = new List<User>();
        }

        public void AddUser(User user, TenantRole role)
        {
           Tenant.AddUser(user, role);
            if (!Users.Contains(user))
            {
                Users.Add(user);
            }
        }
        public void RemoveUser(User user) { 
            Tenant.UserTenants.RemoveAll(ut => ut.User.Id == user.Id);
            Users.Remove(user);
        }
    }
}
