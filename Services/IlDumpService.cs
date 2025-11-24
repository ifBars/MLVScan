using System;
using MelonLoader;
using MelonLoader.Utils;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.IO;
using System.Linq;

namespace MLVScan.Services
{
    public class IlDumpService
    {
        private readonly MelonLogger.Instance _logger;
        private readonly DefaultAssemblyResolver _assemblyResolver;

        public IlDumpService(MelonLogger.Instance logger)
        {
            _logger = logger;
            _assemblyResolver = BuildResolver();
        }

        public bool TryDumpAssembly(string assemblyPath, string outputPath)
        {
            if (string.IsNullOrWhiteSpace(assemblyPath) || string.IsNullOrWhiteSpace(outputPath))
            {
                return false;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

                var readerParameters = new ReaderParameters
                {
                    ReadWrite = false,
                    InMemory = true,
                    ReadSymbols = false,
                    AssemblyResolver = _assemblyResolver
                };

                var assembly = AssemblyDefinition.ReadAssembly(assemblyPath, readerParameters);

                using var writer = new StreamWriter(outputPath);
                writer.WriteLine($"; Full IL dump for {Path.GetFileName(assemblyPath)}");
                writer.WriteLine($"; Generated: {System.DateTime.Now}");
                writer.WriteLine();

                foreach (var module in assembly.Modules)
                {
                    writer.WriteLine($".module {module.Name}");
                    writer.WriteLine();

                    foreach (var type in module.Types)
                    {
                        WriteType(type, writer);
                    }
                }

                _logger?.Msg($"Saved IL dump to: {outputPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger?.Error($"Failed to dump IL for {Path.GetFileName(assemblyPath)}: {ex.Message}");
                return false;
            }
        }

        private DefaultAssemblyResolver BuildResolver()
        {
            var resolver = new DefaultAssemblyResolver();

            var gameDir = MelonEnvironment.GameRootDirectory;
            var melonDir = Path.Combine(gameDir, "MelonLoader");

            resolver.AddSearchDirectory(gameDir);

            if (Directory.Exists(melonDir))
            {
                resolver.AddSearchDirectory(melonDir);

                var managedDir = Path.Combine(melonDir, "Managed");
                if (Directory.Exists(managedDir))
                {
                    resolver.AddSearchDirectory(managedDir);
                }

                var dependenciesDir = Path.Combine(melonDir, "Dependencies");
                if (Directory.Exists(dependenciesDir))
                {
                    resolver.AddSearchDirectory(dependenciesDir);

                    foreach (var dir in Directory.GetDirectories(dependenciesDir, "*", SearchOption.AllDirectories))
                    {
                        resolver.AddSearchDirectory(dir);
                    }
                }
            }

            var gameManagedDir = Path.Combine(gameDir, "Schedule I_Data", "Managed");
            if (Directory.Exists(gameManagedDir))
            {
                resolver.AddSearchDirectory(gameManagedDir);
            }

            return resolver;
        }

        private static void WriteType(TypeDefinition type, StreamWriter writer)
        {
            writer.WriteLine($".class {type.FullName}");

            foreach (var method in type.Methods)
            {
                WriteMethod(method, writer);
            }

            foreach (var nestedType in type.NestedTypes)
            {
                WriteType(nestedType, writer);
            }
        }

        private static void WriteMethod(MethodDefinition method, StreamWriter writer)
        {
            try
            {
                var parameters = string.Join(", ", method.Parameters.Select(p => $"{p.ParameterType.FullName} {p.Name}"));
                writer.WriteLine($"  .method {method.ReturnType.FullName} {method.Name}({parameters})");

                if (!method.HasBody)
                {
                    writer.WriteLine("    // No body (abstract / external)");
                    writer.WriteLine();
                    return;
                }

                writer.WriteLine("  {");
                foreach (var instruction in method.Body.Instructions)
                {
                    var operandText = FormatOperand(instruction.Operand);
                    var line = $"    IL_{instruction.Offset:X4}: {instruction.OpCode}";
                    if (!string.IsNullOrEmpty(operandText))
                    {
                        line += $" {operandText}";
                    }
                    writer.WriteLine(line);
                }
                writer.WriteLine("  }");
                writer.WriteLine();
            }
            catch (Exception ex)
            {
                writer.WriteLine($"    // Failed to dump method {method.Name}: {ex.Message}");
                writer.WriteLine();
            }
        }

        private static string FormatOperand(object operand)
        {
            return operand switch
            {
                null => string.Empty,
                string s => $"\"{s}\"",
                MethodReference mr => mr.FullName,
                FieldReference fr => fr.FullName,
                TypeReference tr => tr.FullName,
                Instruction i => $"IL_{i.Offset:X4}",
                Instruction[] targets => string.Join(", ", targets.Select(t => $"IL_{t.Offset:X4}")),
                _ => operand.ToString() ?? string.Empty
            };
        }
    }
}
