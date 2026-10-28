// Red team round 2, .NET SDK. Copied into tests/TrafficTwin.Sdk.Tests by run.sh (the SDK's internals are
// visible to that assembly only). Invented data only; servers on 127.0.0.1.
//
// RT-DOTNET-1 (low): FleetClient.SendAsync (sdk/dotnet/src/TrafficTwin.Sdk/Fleet/FleetClient.cs) reads the
// response with HttpCompletionOption.ResponseHeadersRead and then loops `while (ReadAsync > 0)`, discarding bytes
// past 8 MiB but never stopping. HttpClient.Timeout does not cover the body once headers are read, and the token
// passed is the agent's lifetime token: a tt-core (or anything answering on the Fleet URL with a valid cert) that
// streams an endless body blocks that loop forever. The heartbeat loop would then never apply a kill switch,
// min_issued_seq or key revocation again (capture stops only at policy_max_age). The cap should end the read
// (fail with a code) and the whole exchange should be bounded by RequestTimeout.
//
// All tests pass since the fixes (regression tests). Run:
//   test/redteam/dotnet/run.sh

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Fleet;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

public class RedTeamRound2Tests
{
    private static (TcpListener, Task) EndlessServer(CancellationToken stop)
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        Task t = Task.Run(async () =>
        {
            byte[] chunk = Encoding.ASCII.GetBytes("10000\r\n" + new string(' ', 0x10000) + "\r\n");
            while (!stop.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await l.AcceptTcpClientAsync(stop); }
                catch (Exception) { return; }
                _ = Task.Run(async () =>
                {
                    using (c)
                    {
                        try
                        {
                            NetworkStream s = c.GetStream();
                            var buf = new byte[8192];
                            await s.ReadAsync(buf, stop); // the request (small)
                            await s.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n"), stop);
                            while (!stop.IsCancellationRequested) await s.WriteAsync(chunk, stop);
                        }
                        catch (Exception) { /* client gone */ }
                    }
                });
            }
        });
        return (l, t);
    }

    [Fact]
    public async Task RedTeam_FleetReadIsBoundedInTime()
    {
        using var stop = new CancellationTokenSource();
        var (l, _) = EndlessServer(stop.Token);
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) }; // the agent sets Timeout = RequestTimeout
        var fc = new FleetClient(http, "http://127.0.0.1:" + port);
        Task call = fc.GetPolicyAsync(null, CancellationToken.None);
        Task done = await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(20)));
        // Fixed: the cap ends the read (FleetException fleet_response_too_large) or, at the latest, the exchange deadline.
        if (done == call && call.IsFaulted) Assert.Equal("fleet_response_too_large", ((FleetException)call.Exception!.InnerException!).Code);
        stop.Cancel();
        l.Stop();
        Assert.True(done == call, "GetPolicyAsync still reading an endless body 20 s after a 2 s RequestTimeout (8 MiB cap does not stop the read)");
    }

    [Fact]
    public async Task RedTeam_FleetStalledBodyHitsTheDeadline()
    {
        using var stop = new CancellationTokenSource();
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        _ = Task.Run(async () =>
        {
            try
            {
                using TcpClient c = await l.AcceptTcpClientAsync(stop.Token);
                NetworkStream s = c.GetStream();
                await s.ReadAsync(new byte[8192], stop.Token);
                await s.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n"), stop.Token);
                await Task.Delay(30_000, stop.Token); // headers sent, then silence
            }
            catch (Exception) { /* done */ }
        });
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var fc = new FleetClient(http, "http://127.0.0.1:" + port);
        Task call = fc.GetPolicyAsync(null, CancellationToken.None);
        Task done = await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(15)));
        stop.Cancel();
        l.Stop();
        Assert.True(done == call, "a body that stalls after the headers was not cut by the 2 s deadline");
    }

    [Fact]
    public void RedTeam_ForeignOrLooseStateFilesAreNotTrusted()
    {
        if (OperatingSystem.IsWindows()) return;
        string home = Path.Combine(Path.GetTempPath(), "tt-rt-" + Guid.NewGuid().ToString("N"));
        string root = Path.Combine(home, ".traffic-twin");
        string dir = Path.Combine(root, "abc");
        Directory.CreateDirectory(dir);
        File.SetUnixFileMode(root, (UnixFileMode)Convert.ToInt32("755", 8));
        File.SetUnixFileMode(dir, (UnixFileMode)Convert.ToInt32("775", 8));
        try
        {
            var seen = new System.Collections.Generic.List<string>();
            var st = new StateStore(dir) { OnUntrusted = seen.Add };
            Assert.True(st.Prepare());
            Assert.Equal((UnixFileMode)Convert.ToInt32("700", 8), File.GetUnixFileMode(root));
            Assert.Equal((UnixFileMode)Convert.ToInt32("700", 8), File.GetUnixFileMode(dir));
            st.WriteText("state.json", "{}");
            Assert.Equal("{}", st.ReadText("state.json"));
            File.SetUnixFileMode(Path.Combine(dir, "state.json"), (UnixFileMode)Convert.ToInt32("666", 8));
            Assert.Null(st.ReadText("state.json"));
            Assert.Equal(new[] { "state_file_untrusted" }, seen);
            st.WriteText("client.key", "K");
            File.SetUnixFileMode(Path.Combine(dir, "client.key"), (UnixFileMode)Convert.ToInt32("644", 8));
            Assert.Equal("K", st.ReadText("client.key"));
            Assert.Equal((UnixFileMode)Convert.ToInt32("600", 8), File.GetUnixFileMode(Path.Combine(dir, "client.key")));
            File.CreateSymbolicLink(Path.Combine(dir, "enrollment.json"), "/etc/hosts");
            Assert.Null(st.ReadText("enrollment.json"));
        }
        finally
        {
            Directory.Delete(home, true);
        }
    }

    [Fact]
    public void RedTeam_StateDirIsTightenedEvenIfItExists()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Path.Combine(Path.GetTempPath(), "tt-rt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.SetUnixFileMode(dir, (UnixFileMode)Convert.ToInt32("777", 8));
        try
        {
            new StateStore(dir).WriteText("client.key", "-----BEGIN PRIVATE KEY-----\ninvented\n-----END PRIVATE KEY-----\n");
            Assert.Equal((UnixFileMode)Convert.ToInt32("700", 8), File.GetUnixFileMode(dir));
            Assert.Equal((UnixFileMode)Convert.ToInt32("600", 8), File.GetUnixFileMode(Path.Combine(dir, "client.key")));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
