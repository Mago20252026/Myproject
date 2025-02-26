using System;

namespace Domain.ValueObjects
{
    public class PhoneNumber
    {
        public string Value { get; private set; }

        public PhoneNumber(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException("Phone number cannot be empty", nameof(value));
            if (!System.Text.RegularExpressions.Regex.IsMatch(value, @"^\+?[1-9]\d{1,14}$"))
                throw new ArgumentException("Invalid phone number format", nameof(value));

            Value = value;
        }

        public override string ToString()
        {
            return Value;
        }
    }
}