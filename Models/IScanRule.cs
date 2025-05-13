using Mono.Cecil;

namespace MLVScan.Models
{
    public interface IScanRule
    {
        bool IsSuspicious(MethodReference method);
        string Description { get; }
        string Severity { get; }
    }
}