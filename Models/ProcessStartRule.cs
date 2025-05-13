﻿using Mono.Cecil;

namespace MLVScan.Models
{
    public class ProcessStartRule : IScanRule
    {
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return (typeName.Contains("System.Diagnostics.Process") && methodName == "Start") ||
                   (typeName.Contains("Process") && methodName == "Start" ||
                    typeName.Contains("Process") && methodName == "Start");
        }

        public string Description => "Detected Process.Start call which could execute arbitrary programs.";

        public string Severity => "Critical";
    }
}