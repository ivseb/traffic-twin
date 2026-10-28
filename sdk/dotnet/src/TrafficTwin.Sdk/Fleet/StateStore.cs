using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TrafficTwin.Sdk.Fleet;

/// <summary>
/// Local state of the source: enrollment (certificate, CA chain, pinned keys), private key, signed policy cache, kill switch.
/// Directory 0700, files 0600 (on Unix), atomic replace. On Windows the permissions are those inherited from the profile directory.
/// <para>
/// Trust (Unix): the directory (and <c>~/.traffic-twin</c>, the parent of the default one) is created 0700 and a wider
/// pre-existing one is repaired; a chmod that fails means we do not own it, and the directory is refused
/// (<see cref="Prepare"/> returns false, the agent then uses a private temporary directory). A state file is read only
/// when it is not a symlink, is not group/world-writable and a chmod to 0600 succeeds (which proves we own it);
/// otherwise it reads as absent and <see cref="OnUntrusted"/> is told (never its contents).
/// </para>
/// </summary>
internal sealed class StateStore
{
    public string Dir { get; }

    public StateStore(string dir) { Dir = dir; }

    /// <summary>Called with a short code when a state file or directory is refused.</summary>
    public Action<string>? OnUntrusted { get; set; }

    private const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode LooseWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    /// <summary>Creates/validates the directory; false when it cannot be trusted (not ours, cannot be made 0700).</summary>
    public bool Prepare()
    {
        try { Ensure(); return true; }
        catch (Exception) { return false; }
    }

    public static string DefaultDir(string enrollUrl, string serviceName)
    {
        string id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(enrollUrl + "\0" + serviceName))).ToLowerInvariant().Substring(0, 16);
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home)) home = Path.GetTempPath();
        return Path.Combine(home, ".traffic-twin", id);
    }

    private void Ensure()
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(Dir);
            return;
        }
        string? parent = Path.GetDirectoryName(Dir);
        if (parent != null && Path.GetFileName(parent) == ".traffic-twin") MakePrivate(parent); // ~/.traffic-twin/<id>
        MakePrivate(Dir);
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void MakePrivate(string dir)
    {
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir, Private);
        try { File.SetUnixFileMode(dir, Private); }
        catch (Exception e) { throw new UnauthorizedAccessException("state_dir_not_owned", e); } // chmod fails when we are not the owner
    }

    private bool Trusted(string path)
    {
        if (OperatingSystem.IsWindows()) return true;
        try
        {
            var fi = new FileInfo(path);
            if (fi.LinkTarget == null && (fi.UnixFileMode & LooseWrite) == 0)
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); // ours (else it throws); also tightens 0644 -> 0600
                return true;
            }
        }
        catch (Exception) { /* not ours */ }
        try { OnUntrusted?.Invoke("state_file_untrusted"); }
        catch (Exception) { /* a reporting error must not matter */ }
        return false;
    }

    public string? ReadText(string name)
    {
        string path = Path.Combine(Dir, name);
        try
        {
            if (!File.Exists(path) || !Trusted(path)) return null;
            return File.ReadAllText(path, new UTF8Encoding(false));
        }
        catch (Exception) { return null; }
    }

    public T? ReadJson<T>(string name) where T : class
    {
        string? t = ReadText(name);
        if (t == null) return null;
        try { return JsonSerializer.Deserialize<T>(t); }
        catch (Exception) { return null; }
    }

    public void WriteText(string name, string text)
    {
        Ensure();
        string tmp = Path.Combine(Dir, "." + name + "." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");
        var opts = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) opts.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var fs = new FileStream(tmp, opts))
        {
            byte[] data = new UTF8Encoding(false).GetBytes(text);
            fs.Write(data, 0, data.Length);
            fs.Flush(true);
        }
        File.Move(tmp, Path.Combine(Dir, name), overwrite: true);
    }

    public void WriteJson<T>(string name, T value) => WriteText(name, JsonSerializer.Serialize(value));

    public void Remove(string name)
    {
        try { File.Delete(Path.Combine(Dir, name)); }
        catch (Exception) { /* absent */ }
    }
}
