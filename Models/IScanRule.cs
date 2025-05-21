using Mono.Cecil;

namespace MLVScan.Models
{
    public interface IScanRule
    {
        string Description { get; }
        string Severity { get; }
        bool IsSuspicious(MethodReference method);
    }
}