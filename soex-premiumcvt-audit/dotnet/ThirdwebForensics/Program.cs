using System.Text.Json;
using System.Text.RegularExpressions;
using Thirdweb;

namespace ThirdwebForensics;

/// <summary>
/// thirdweb .NET read-only EVM forensic recon — the .NET sibling of
/// <c>scripts/evm_recon.ts</c>. It dynamically leverages the thirdweb .NET SDK
/// (https://portal.thirdweb.com/dotnet) to resolve a live contract's ABI and
/// then runs the same static EVM hunting lanes (access control, upgradeability,
/// arbitrary call/delegatecall, token approval, signature replay, reentrancy,
/// value-moving math, self-destruct) over it.
///
/// Guardrails: read-only only. It fetches the ABI and (optionally) calls a
/// constant <c>owner()</c> getter; it never creates a wallet, builds, signs, or
/// sends a transaction. Set READ_ONLY=false is rejected.
///
/// Env:
///   THIRDWEB_SECRET_KEY (server) or THIRDWEB_CLIENT_ID
///   EVM_CHAIN_ID  numeric chain id (e.g. 1, 56, 4200)
///   EVM_ADDRESS   0x contract address
///   EVIDENCE_DIR  output dir (default ./evidence)
/// </summary>
internal static class Program
{
    private static async Task<int> Main()
    {
        if (Environment.GetEnvironmentVariable("READ_ONLY") == "false")
        {
            Console.Error.WriteLine("READ_ONLY must stay true — recon only reads, never sends.");
            return 2;
        }

        var secretKey = Environment.GetEnvironmentVariable("THIRDWEB_SECRET_KEY")?.Trim();
        var clientId = Environment.GetEnvironmentVariable("THIRDWEB_CLIENT_ID")?.Trim();
        var chainIdRaw = Environment.GetEnvironmentVariable("EVM_CHAIN_ID")?.Trim();
        var address = Environment.GetEnvironmentVariable("EVM_ADDRESS")?.Trim();

        if (string.IsNullOrEmpty(secretKey) && string.IsNullOrEmpty(clientId))
        {
            Console.Error.WriteLine(
                "Provide THIRDWEB_SECRET_KEY (server) or THIRDWEB_CLIENT_ID. " +
                "Get one at https://thirdweb.com/create-api-key.");
            return 2;
        }
        if (string.IsNullOrEmpty(chainIdRaw) || !System.Numerics.BigInteger.TryParse(chainIdRaw, out var chainId))
        {
            Console.Error.WriteLine("EVM_CHAIN_ID must be a numeric chain id (e.g. 1, 56, 4200).");
            return 2;
        }
        if (string.IsNullOrEmpty(address))
        {
            Console.Error.WriteLine("EVM_ADDRESS is required.");
            return 2;
        }

        var client = string.IsNullOrEmpty(secretKey)
            ? ThirdwebClient.Create(clientId: clientId)
            : ThirdwebClient.Create(secretKey: secretKey);

        // --- read-only surface resolution via thirdweb ---------------------
        var abiJson = await ThirdwebContract.FetchAbi(client, address, chainId);
        var functions = EvmHeuristics.ParseFunctions(abiJson);
        var findings = EvmHeuristics.Analyze(functions);

        // Best-effort read of a constant owner()/admin getter (read-only call).
        string? owner = null;
        try
        {
            var contract = await ThirdwebContract.Create(client, address, chainId, abiJson);
            owner = await ThirdwebContract.Read<string>(contract, "owner");
        }
        catch
        {
            // No owner() getter, or read failed — not fatal for recon.
        }

        var evidenceDir = Environment.GetEnvironmentVariable("EVIDENCE_DIR") ?? "./evidence";
        Directory.CreateDirectory(evidenceDir);
        var stamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH-mm-ss");
        var outPath = Path.Combine(evidenceDir, $"dotnet-evm-recon-{stamp}.json");

        var payload = new
        {
            collectedAt = DateTime.UtcNow.ToString("o"),
            readOnly = true,
            sdk = "thirdweb-dotnet",
            chainId = chainId.ToString(),
            address,
            owner,
            functionCount = functions.Count,
            findings,
        };
        await File.WriteAllTextAsync(
            outPath,
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine($"Wrote {outPath}");
        Console.WriteLine(
            $"Chain {chainId}  Contract {address}  Functions: {functions.Count}  " +
            $"Findings: {findings.Count}  Owner: {owner ?? "n/a"}");
        foreach (var f in findings)
        {
            Console.WriteLine($"  [{f.Severity}] {f.Lane}  {f.Function} — {f.Title}");
        }
        return 0;
    }
}

internal sealed record EvmFunction(string Name, string StateMutability, IReadOnlyList<string> InputTypes)
{
    public bool ReadOnly => StateMutability is "view" or "pure";
    public bool Payable => StateMutability == "payable";
}

internal sealed record EvmFinding(string Lane, string Severity, string Function, string Title, string Detail);

/// <summary>
/// A compact C# port of the static EVM hunting lanes in
/// <c>scripts/lib/evm_analyze.ts</c>, so the .NET path produces the same class
/// of candidate findings. Candidates only — confirm by hand (docs/03).
/// </summary>
internal static class EvmHeuristics
{
    private static readonly Regex Privileged = new(
        "(mint|burn|withdraw|setowner|setadmin|set_|setconfig|configure|pause|unpause|upgrade|migrate|initialize|^init$|rescue|sweep|drain|seize|setfee|setprice|whitelist|blacklist|grantrole|revokerole|addminter|removeminter|setminter|settreasury|setvault)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Upgrade = new(
        "(upgradeto|upgradetoandcall|setimplementation|changeadmin|transferownership|renounceownership)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ArbitraryCall = new(
        "(^execute$|^call$|multicall|functioncall|delegatecall|aggregate|^batch|forward|relay)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Approval = new(
        "(^approve$|increaseallowance|setapprovalforall|^permit$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Signature = new(
        "(permit|withsig|metatx|executemeta|claimwithsig)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ValueOut = new(
        "(withdraw|claim|redeem|unstake|transfer|send|payout|distribute|harvest|collect)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SelfDestruct = new(
        "(selfdestruct|destroy|^kill$|terminate)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<EvmFunction> ParseFunctions(string abiJson)
    {
        var functions = new List<EvmFunction>();
        using var doc = JsonDocument.Parse(abiJson);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return functions;
        }

        foreach (var entry in doc.RootElement.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var type = entry.TryGetProperty("type", out var t) ? t.GetString() : "function";
            if (type != "function")
            {
                continue;
            }
            var name = entry.TryGetProperty("name", out var n) ? n.GetString() ?? "unknown" : "unknown";
            var sm = entry.TryGetProperty("stateMutability", out var s) ? s.GetString() ?? "nonpayable" : "nonpayable";
            var inputs = new List<string>();
            if (entry.TryGetProperty("inputs", out var ins) && ins.ValueKind == JsonValueKind.Array)
            {
                foreach (var inp in ins.EnumerateArray())
                {
                    inputs.Add(inp.TryGetProperty("type", out var ity) ? ity.GetString() ?? "unknown" : "unknown");
                }
            }
            functions.Add(new EvmFunction(name, sm, inputs));
        }
        return functions;
    }

    public static List<EvmFinding> Analyze(IReadOnlyList<EvmFunction> functions)
    {
        var findings = new List<EvmFinding>();
        foreach (var fn in functions)
        {
            if (!fn.ReadOnly && Privileged.IsMatch(fn.Name))
            {
                findings.Add(new EvmFinding("EA-access-control", "high", fn.Name,
                    "Privileged function — verify access control",
                    "State-mutating privileged function; the ABI cannot prove an owner/role modifier."));
            }
            if (Upgrade.IsMatch(fn.Name))
            {
                findings.Add(new EvmFinding("EB-upgradeability", "critical", fn.Name,
                    "Upgrade / ownership-authority function",
                    "Changes implementation/admin/ownership; verify current authority + timelock."));
            }
            var hasAddressBytes = fn.InputTypes.Contains("address")
                && fn.InputTypes.Any(x => x == "bytes" || x.StartsWith("bytes"));
            if (!fn.ReadOnly && (ArbitraryCall.IsMatch(fn.Name) || hasAddressBytes))
            {
                findings.Add(new EvmFinding("EC-arbitrary-call", "critical", fn.Name,
                    "Arbitrary external call / delegatecall seam",
                    "Forwards a call to a caller-supplied target/calldata; verify target allow-listing."));
            }
            if (Approval.IsMatch(fn.Name))
            {
                findings.Add(new EvmFinding("ED-token-approval", "medium", fn.Name,
                    "Approval surface — verify allowance handling",
                    "Approval race / infinite approval / permit replay seam."));
            }
            if (!fn.ReadOnly && Signature.IsMatch(fn.Name))
            {
                findings.Add(new EvmFinding("EE-signature-replay", "high", fn.Name,
                    "Signature-verifying function — verify nonce/deadline + EIP-712 domain",
                    "Confirm per-signer nonce, deadline, and chain-bound domain separation."));
            }
            if (!fn.ReadOnly && (ValueOut.IsMatch(fn.Name) || fn.Payable))
            {
                findings.Add(new EvmFinding("EF-reentrancy", "high", fn.Name,
                    "Value-moving function — verify reentrancy guard / CEI",
                    "Confirm checks-effects-interactions and a reentrancy guard."));
            }
            if (SelfDestruct.IsMatch(fn.Name))
            {
                findings.Add(new EvmFinding("EH-self-destruct", "high", fn.Name,
                    "Self-destruct / terminate function",
                    "May brick the contract or strand funds; verify strict access control."));
            }
        }
        return findings;
    }
}
