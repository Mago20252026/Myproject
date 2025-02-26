using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class SecurityEventRequest
    {
        public string EventType { get; set; }
        public string Details { get; set; }
    }
}