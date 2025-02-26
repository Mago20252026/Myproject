using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainEvents
{
    public class UserRegisteredEvent 
    {
        public Guid UserId { get; private set; }
        public string UserName { get; private set; }
        public string Email { get; private set; }

        public UserRegisteredEvent(Guid userId, string username, string email)
        {
            UserId = userId;
            UserName = username;
            Email = email;
        }
    }
}
