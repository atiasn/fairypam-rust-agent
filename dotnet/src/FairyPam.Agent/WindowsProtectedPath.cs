using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FairyPam.Agent;

internal static class WindowsProtectedPath
{
    private static readonly SecurityIdentifier Administrators = new(
        WellKnownSidType.BuiltinAdministratorsSid,
        null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new(
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly HashSet<SecurityIdentifier> TrustedOwners =
    [
        Administrators,
        System,
        TrustedInstaller,
    ];
    private static readonly HashSet<SecurityIdentifier> TrustedWritePrincipals =
    [
        Administrators,
        System,
        new(WellKnownSidType.CreatorOwnerSid, null),
        TrustedInstaller,
    ];

    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData
        | FileSystemRights.AppendData
        | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.WriteAttributes
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.Delete
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership;

    public static string AgentStateRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FairyPam.Agent",
        "Agent");

    public static void VerifyInstallRoot(string path)
    {
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        string programFiles = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        RequireDescendant(fullPath, programFiles, "install.path_unprotected");
        VerifyDirectoryChain(fullPath, programFiles);

        string executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("install.executable_missing");
        VerifyProtectedFile(executable, fullPath);
    }

    public static void VerifyProtectedFile(string path, string protectedRoot)
    {
        string fullPath = Path.GetFullPath(path);
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(protectedRoot));
        RequireDescendant(fullPath, fullRoot, "file.path_unprotected");

        FileInfo file = new(fullPath);
        if (!file.Exists)
        {
            throw new InvalidOperationException("file.missing");
        }
        VerifyNode(file);
        VerifyDirectoryChain(file.Directory!.FullName, fullRoot);
    }

    public static void EnsurePrivateDirectory(string path)
    {
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        string stateRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AgentStateRoot));
        if (!fullPath.Equals(stateRoot, StringComparison.OrdinalIgnoreCase))
        {
            RequireDescendant(fullPath, stateRoot, "state.path_unprotected");
        }

        string commonData = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));
        RequireDescendant(stateRoot, commonData, "state.path_unprotected");

        CreateProtectedDirectory(Path.Combine(commonData, "FairyPam.Agent"));
        CreateProtectedDirectory(stateRoot);
        string relative = Path.GetRelativePath(stateRoot, fullPath);
        if (relative != ".")
        {
            string current = stateRoot;
            foreach (string segment in relative.Split(Path.DirectorySeparatorChar))
            {
                current = Path.Combine(current, segment);
                CreateProtectedDirectory(current);
            }
        }
        VerifyDirectoryChain(fullPath, Path.Combine(commonData, "FairyPam.Agent"));
    }

    public static FileStream AcquireMachineLock()
    {
        EnsurePrivateDirectory(AgentStateRoot);
        string path = Path.Combine(AgentStateRoot, "agent.lock");
        FileInfo file = new(path);
        FileStream stream = file.Exists
            ? new FileStream(
                path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough)
            : file.Create(
                FileMode.CreateNew,
                FileSystemRights.FullControl,
                FileShare.None,
                1,
                FileOptions.WriteThrough,
                CreatePrivateFileSecurity());
        try
        {
            VerifyProtectedFile(path, AgentStateRoot);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static void CreateProtectedDirectory(string path)
    {
        DirectoryInfo directory = new(path);
        if (!directory.Exists)
        {
            directory.Create(CreatePrivateSecurity());
        }
        VerifyNode(directory);
    }

    private static DirectorySecurity CreatePrivateSecurity()
    {
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            System,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static FileSecurity CreatePrivateFileSecurity()
    {
        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        security.AddAccessRule(new FileSystemAccessRule(
            System,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        return security;
    }

    private static void VerifyDirectoryChain(string path, string trustedRoot)
    {
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trustedRoot));
        if (!fullPath.Equals(fullRoot, StringComparison.OrdinalIgnoreCase))
        {
            RequireDescendant(fullPath, fullRoot, "path.outside_trusted_root");
        }

        DirectoryInfo? current = new(fullPath);
        while (current is not null)
        {
            if (!current.Exists)
            {
                throw new InvalidOperationException("path.missing");
            }
            VerifyNode(current);
            if (current.FullName.Equals(fullRoot, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            current = current.Parent;
        }
        throw new InvalidOperationException("path.outside_trusted_root");
    }

    private static void VerifyNode(FileSystemInfo node)
    {
        node.Refresh();
        if (!node.Exists || (node.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("path.reparse_or_missing");
        }

        FileSystemSecurity security = node switch
        {
            DirectoryInfo directory => directory.GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner),
            FileInfo file => file.GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner),
            _ => throw new InvalidOperationException("path.kind_invalid"),
        };
        SecurityIdentifier? owner = security.GetOwner(
            typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !TrustedOwners.Contains(owner))
        {
            throw new InvalidOperationException("path.owner_untrusted");
        }

        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && rule.IdentityReference is SecurityIdentifier sid
                && !TrustedWritePrincipals.Contains(sid)
                && (rule.FileSystemRights & WriteRights) != 0)
            {
                throw new InvalidOperationException("path.writer_untrusted");
            }
        }
    }

    private static void RequireDescendant(string path, string root, string code)
    {
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(code);
        }
    }
}
