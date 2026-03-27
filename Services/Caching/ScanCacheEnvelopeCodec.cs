using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using MLVScan.Abstractions;
using MLVScan.Models;

namespace MLVScan.Services.Caching
{
    internal static class ScanCacheEnvelopeCodec
    {
        private const int EnvelopeMagic = 0x4D4C5643;
        private const int EnvelopeVersion = 2;

        public static byte[] SerializePayload(ScanCacheEntryPayload payload)
        {
            using var memory = new MemoryStream();
            using var writer = new BinaryWriter(memory, Encoding.UTF8, true);
            WritePayload(writer, payload ?? new ScanCacheEntryPayload());
            writer.Flush();
            return memory.ToArray();
        }

        public static byte[] SerializeEnvelope(string signature, byte[] payloadBytes)
        {
            var bytes = payloadBytes ?? Array.Empty<byte>();

            using var memory = new MemoryStream();
            using var writer = new BinaryWriter(memory, Encoding.UTF8, true);
            writer.Write(EnvelopeMagic);
            writer.Write(EnvelopeVersion);
            WriteString(writer, signature);
            writer.Write(bytes.Length);
            writer.Write(bytes);
            writer.Flush();
            return memory.ToArray();
        }

        public static bool TryDeserializeEnvelope(
            byte[] envelopeBytes,
            out string signature,
            out byte[] payloadBytes)
        {
            signature = string.Empty;
            payloadBytes = Array.Empty<byte>();

            if (envelopeBytes == null || envelopeBytes.Length == 0)
            {
                return false;
            }

            try
            {
                using var memory = new MemoryStream(envelopeBytes, writable: false);
                using var reader = new BinaryReader(memory, Encoding.UTF8, true);

                if (reader.ReadInt32() != EnvelopeMagic || reader.ReadInt32() != EnvelopeVersion)
                {
                    return false;
                }

                signature = ReadString(reader);
                var payloadLength = reader.ReadInt32();
                if (payloadLength < 0 || payloadLength > (memory.Length - memory.Position))
                {
                    return false;
                }

                payloadBytes = reader.ReadBytes(payloadLength);
                if (payloadBytes.Length != payloadLength)
                {
                    return false;
                }

                return true;
            }
            catch
            {
                signature = string.Empty;
                payloadBytes = Array.Empty<byte>();
                return false;
            }
        }

        public static ScanCacheEntryPayload DeserializePayload(byte[] payloadBytes)
        {
            using var memory = new MemoryStream(payloadBytes, writable: false);
            using var reader = new BinaryReader(memory, Encoding.UTF8, true);

            return new ScanCacheEntryPayload
            {
                CanonicalPath = ReadString(reader),
                RealPath = ReadString(reader),
                FileIdentity = ReadFileIdentity(reader),
                Sha256 = ReadString(reader),
                ScannerFingerprint = ReadString(reader),
                ResolverFingerprint = ReadString(reader),
                CreatedUtc = DateTime.FromBinary(reader.ReadInt64()),
                VerifiedUtc = DateTime.FromBinary(reader.ReadInt64()),
                Result = ReadResult(reader)
            };
        }

        private static void WritePayload(BinaryWriter writer, ScanCacheEntryPayload payload)
        {
            WriteString(writer, payload.CanonicalPath);
            WriteString(writer, payload.RealPath);
            WriteFileIdentity(writer, payload.FileIdentity);
            WriteString(writer, payload.Sha256);
            WriteString(writer, payload.ScannerFingerprint);
            WriteString(writer, payload.ResolverFingerprint);
            writer.Write(payload.CreatedUtc.ToBinary());
            writer.Write(payload.VerifiedUtc.ToBinary());
            WriteResult(writer, payload.Result);
        }

        private static void WriteFileIdentity(BinaryWriter writer, FileIdentitySnapshot identity)
        {
            var value = identity ?? new FileIdentitySnapshot();
            WriteString(writer, value.Platform);
            writer.Write(value.HasStrongIdentity);
            WriteString(writer, value.IdentityKey);
            writer.Write(value.Size);
            writer.Write(value.LastWriteUtcTicks);
            writer.Write(value.ChangeUtcTicks);
            writer.Write(value.IsSymlinkOrReparsePoint);
        }

        private static FileIdentitySnapshot ReadFileIdentity(BinaryReader reader)
        {
            return new FileIdentitySnapshot
            {
                Platform = ReadString(reader),
                HasStrongIdentity = reader.ReadBoolean(),
                IdentityKey = ReadString(reader),
                Size = reader.ReadInt64(),
                LastWriteUtcTicks = reader.ReadInt64(),
                ChangeUtcTicks = reader.ReadInt64(),
                IsSymlinkOrReparsePoint = reader.ReadBoolean()
            };
        }

        private static void WriteResult(BinaryWriter writer, ScannedPluginResult result)
        {
            var value = result ?? new ScannedPluginResult();
            WriteString(writer, value.FilePath);
            WriteString(writer, value.FileHash);
            WriteFindings(writer, value.Findings);
            WriteThreatVerdict(writer, value.ThreatVerdict);
            WriteScanStatus(writer, value.ScanStatus);
        }

        private static ScannedPluginResult ReadResult(BinaryReader reader)
        {
            return new ScannedPluginResult
            {
                FilePath = ReadString(reader),
                FileHash = ReadString(reader),
                Findings = ReadFindings(reader),
                ThreatVerdict = ReadThreatVerdict(reader) ?? new ThreatVerdictInfo(),
                ScanStatus = ReadScanStatus(reader) ?? new ScanStatusInfo()
            };
        }

        private static void WriteFindings(BinaryWriter writer, List<ScanFinding> findings)
        {
            var values = findings ?? new List<ScanFinding>();
            writer.Write(values.Count);
            foreach (var finding in values)
            {
                WriteFinding(writer, finding);
            }
        }

        private static List<ScanFinding> ReadFindings(BinaryReader reader)
        {
            var count = reader.ReadInt32();
            var findings = new List<ScanFinding>(Math.Max(count, 0));
            for (var i = 0; i < count; i++)
            {
                findings.Add(ReadFinding(reader));
            }

            return findings;
        }

        private static void WriteFinding(BinaryWriter writer, ScanFinding finding)
        {
            var value = finding ?? new ScanFinding(string.Empty, string.Empty);
            WriteString(writer, value.Location);
            WriteString(writer, value.Description);
            writer.Write((int)value.Severity);
            WriteString(writer, value.CodeSnippet);
            WriteString(writer, value.RuleId);
            WriteDeveloperGuidance(writer, value.DeveloperGuidance);
            writer.Write(value.BypassCompanionCheck);
            writer.Write(value.RiskScore.HasValue);
            if (value.RiskScore.HasValue)
            {
                writer.Write(value.RiskScore.Value);
            }

            WriteCallChain(writer, value.CallChain);
            WriteDataFlowChain(writer, value.DataFlowChain);
        }

        private static ScanFinding ReadFinding(BinaryReader reader)
        {
            var finding = new ScanFinding(
                ReadString(reader),
                ReadString(reader),
                (Severity)reader.ReadInt32(),
                ReadString(reader))
            {
                RuleId = ReadString(reader),
                DeveloperGuidance = ReadDeveloperGuidance(reader),
                BypassCompanionCheck = reader.ReadBoolean()
            };

            if (reader.ReadBoolean())
            {
                finding.RiskScore = reader.ReadInt32();
            }

            finding.CallChain = ReadCallChain(reader);
            finding.DataFlowChain = ReadDataFlowChain(reader);
            return finding;
        }

        private static void WriteDeveloperGuidance(BinaryWriter writer, IDeveloperGuidance guidance)
        {
            writer.Write(guidance != null);
            if (guidance == null)
            {
                return;
            }

            WriteString(writer, guidance.Remediation);
            WriteString(writer, guidance.DocumentationUrl);
            WriteStringArray(writer, guidance.AlternativeApis);
            writer.Write(guidance.IsRemediable);
        }

        private static IDeveloperGuidance ReadDeveloperGuidance(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            return new DeveloperGuidance(
                ReadString(reader),
                ReadString(reader),
                ReadStringArray(reader),
                reader.ReadBoolean());
        }

        private static void WriteThreatVerdict(BinaryWriter writer, ThreatVerdictInfo verdict)
        {
            writer.Write(verdict != null);
            if (verdict == null)
            {
                return;
            }

            writer.Write((int)verdict.Kind);
            WriteString(writer, verdict.Title);
            WriteString(writer, verdict.Summary);
            writer.Write(verdict.Confidence);
            writer.Write(verdict.ShouldBypassThreshold);
            WriteThreatFamily(writer, verdict.PrimaryFamily);
            WriteThreatFamilies(writer, verdict.Families);
        }

        private static ThreatVerdictInfo ReadThreatVerdict(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            return new ThreatVerdictInfo
            {
                Kind = (ThreatVerdictKind)reader.ReadInt32(),
                Title = ReadString(reader),
                Summary = ReadString(reader),
                Confidence = reader.ReadDouble(),
                ShouldBypassThreshold = reader.ReadBoolean(),
                PrimaryFamily = ReadThreatFamily(reader),
                Families = ReadThreatFamilies(reader)
            };
        }

        private static void WriteScanStatus(BinaryWriter writer, ScanStatusInfo scanStatus)
        {
            writer.Write(scanStatus != null);
            if (scanStatus == null)
            {
                return;
            }

            writer.Write((int)scanStatus.Kind);
            WriteString(writer, scanStatus.Title);
            WriteString(writer, scanStatus.Summary);
        }

        private static ScanStatusInfo ReadScanStatus(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            return new ScanStatusInfo
            {
                Kind = (ScanStatusKind)reader.ReadInt32(),
                Title = ReadString(reader),
                Summary = ReadString(reader)
            };
        }

        private static void WriteThreatFamilies(BinaryWriter writer, List<ThreatFamilyReference> families)
        {
            var values = families ?? new List<ThreatFamilyReference>();
            writer.Write(values.Count);
            foreach (var family in values)
            {
                WriteThreatFamily(writer, family);
            }
        }

        private static List<ThreatFamilyReference> ReadThreatFamilies(BinaryReader reader)
        {
            var count = reader.ReadInt32();
            var families = new List<ThreatFamilyReference>(Math.Max(count, 0));
            for (var i = 0; i < count; i++)
            {
                families.Add(ReadThreatFamily(reader));
            }

            return families;
        }

        private static void WriteThreatFamily(BinaryWriter writer, ThreatFamilyReference family)
        {
            writer.Write(family != null);
            if (family == null)
            {
                return;
            }

            WriteString(writer, family.FamilyId);
            WriteString(writer, family.DisplayName);
            WriteString(writer, family.Summary);
            WriteString(writer, family.MatchKind);
            WriteString(writer, family.TechnicalName);
            WriteString(writer, family.ReferenceUrl);
            writer.Write(family.Confidence);
            writer.Write(family.ExactHashMatch);
            WriteStringList(writer, family.MatchedRules);
            WriteStringList(writer, family.Evidence);
        }

        private static ThreatFamilyReference ReadThreatFamily(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            return new ThreatFamilyReference
            {
                FamilyId = ReadString(reader),
                DisplayName = ReadString(reader),
                Summary = ReadString(reader),
                MatchKind = ReadString(reader),
                TechnicalName = ReadString(reader),
                ReferenceUrl = ReadString(reader),
                Confidence = reader.ReadDouble(),
                ExactHashMatch = reader.ReadBoolean(),
                MatchedRules = ReadStringList(reader),
                Evidence = ReadStringList(reader)
            };
        }

        private static void WriteCallChain(BinaryWriter writer, CallChain callChain)
        {
            writer.Write(callChain != null);
            if (callChain == null)
            {
                return;
            }

            WriteString(writer, callChain.ChainId);
            WriteString(writer, callChain.RuleId);
            writer.Write((int)callChain.Severity);
            WriteString(writer, callChain.Summary);
            writer.Write(callChain.Nodes?.Count ?? 0);
            if (callChain.Nodes != null)
            {
                foreach (var node in callChain.Nodes)
                {
                    WriteCallChainNode(writer, node);
                }
            }
        }

        private static CallChain ReadCallChain(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            var callChain = new CallChain(
                ReadString(reader),
                ReadString(reader),
                (Severity)reader.ReadInt32(),
                ReadString(reader));

            var nodeCount = reader.ReadInt32();
            for (var i = 0; i < nodeCount; i++)
            {
                callChain.AppendNode(ReadCallChainNode(reader));
            }

            return callChain;
        }

        private static void WriteCallChainNode(BinaryWriter writer, CallChainNode node)
        {
            var value = node ?? new CallChainNode(string.Empty, string.Empty, CallChainNodeType.IntermediateCall);
            WriteString(writer, value.Location);
            WriteString(writer, value.Description);
            writer.Write((int)value.NodeType);
            WriteString(writer, value.CodeSnippet);
        }

        private static CallChainNode ReadCallChainNode(BinaryReader reader)
        {
            return new CallChainNode(
                ReadString(reader),
                ReadString(reader),
                (CallChainNodeType)reader.ReadInt32(),
                ReadString(reader));
        }

        private static void WriteDataFlowChain(BinaryWriter writer, DataFlowChain dataFlowChain)
        {
            writer.Write(dataFlowChain != null);
            if (dataFlowChain == null)
            {
                return;
            }

            WriteString(writer, dataFlowChain.ChainId);
            WriteString(writer, dataFlowChain.SourceVariable);
            writer.Write((int)dataFlowChain.Pattern);
            writer.Write((int)dataFlowChain.Severity);
            WriteString(writer, dataFlowChain.Summary);
            WriteString(writer, dataFlowChain.MethodLocation);
            writer.Write(dataFlowChain.IsCrossMethod);
            WriteStringList(writer, dataFlowChain.InvolvedMethods);
            writer.Write(dataFlowChain.Nodes?.Count ?? 0);
            if (dataFlowChain.Nodes != null)
            {
                foreach (var node in dataFlowChain.Nodes)
                {
                    WriteDataFlowNode(writer, node);
                }
            }
        }

        private static DataFlowChain ReadDataFlowChain(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            var chainId = ReadString(reader);
            var sourceVariable = ReadString(reader);
            var pattern = (DataFlowPattern)reader.ReadInt32();
            var severity = (Severity)reader.ReadInt32();
            var summary = ReadString(reader);
            var methodLocation = ReadString(reader);

            var dataFlowChain = new DataFlowChain(chainId, pattern, severity, summary, methodLocation)
            {
                SourceVariable = sourceVariable,
                IsCrossMethod = reader.ReadBoolean(),
                InvolvedMethods = ReadStringList(reader)
            };

            var nodeCount = reader.ReadInt32();
            for (var i = 0; i < nodeCount; i++)
            {
                dataFlowChain.AppendNode(ReadDataFlowNode(reader));
            }

            return dataFlowChain;
        }

        private static void WriteDataFlowNode(BinaryWriter writer, DataFlowNode node)
        {
            var value = node ?? new DataFlowNode(string.Empty, string.Empty, DataFlowNodeType.Intermediate, string.Empty, 0);
            WriteString(writer, value.Location);
            WriteString(writer, value.Operation);
            writer.Write((int)value.NodeType);
            WriteString(writer, value.DataDescription);
            writer.Write(value.InstructionOffset);
            WriteString(writer, value.CodeSnippet);
            WriteString(writer, value.MethodKey);
            writer.Write(value.IsMethodBoundary);
            WriteString(writer, value.TargetMethodKey);
        }

        private static DataFlowNode ReadDataFlowNode(BinaryReader reader)
        {
            var node = new DataFlowNode(
                ReadString(reader),
                ReadString(reader),
                (DataFlowNodeType)reader.ReadInt32(),
                ReadString(reader),
                reader.ReadInt32(),
                ReadString(reader),
                ReadString(reader))
            {
                IsMethodBoundary = reader.ReadBoolean(),
                TargetMethodKey = ReadString(reader)
            };

            return node;
        }

        private static void WriteStringList(BinaryWriter writer, List<string> values)
        {
            var list = values ?? new List<string>();
            writer.Write(list.Count);
            foreach (var value in list)
            {
                WriteString(writer, value);
            }
        }

        private static List<string> ReadStringList(BinaryReader reader)
        {
            var count = reader.ReadInt32();
            var values = new List<string>(Math.Max(count, 0));
            for (var i = 0; i < count; i++)
            {
                values.Add(ReadString(reader));
            }

            return values;
        }

        private static void WriteStringArray(BinaryWriter writer, string[] values)
        {
            writer.Write(values != null);
            if (values == null)
            {
                return;
            }

            writer.Write(values.Length);
            foreach (var value in values)
            {
                WriteString(writer, value);
            }
        }

        private static string[] ReadStringArray(BinaryReader reader)
        {
            if (!reader.ReadBoolean())
            {
                return null;
            }

            var count = reader.ReadInt32();
            var values = new string[Math.Max(count, 0)];
            for (var i = 0; i < count; i++)
            {
                values[i] = ReadString(reader);
            }

            return values;
        }

        private static void WriteString(BinaryWriter writer, string value)
        {
            writer.Write(value != null);
            if (value != null)
            {
                writer.Write(value);
            }
        }

        private static string ReadString(BinaryReader reader)
        {
            return reader.ReadBoolean() ? reader.ReadString() : string.Empty;
        }
    }
}
