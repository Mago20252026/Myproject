using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Domain.ValueObjects
{
    public class Email
    {
        public string Value { get; private init; }

        public Email(string value)
        {
            if (!Regex.IsMatch(value, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
                throw new Exception("Invalid email format.");

            Value = value;
        }

        public override string ToString()
        {
            return Value;
        }
    }
}