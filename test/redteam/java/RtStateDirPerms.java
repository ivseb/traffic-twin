// RT-JAVA-2 (low): the Java SDK keeps a pre-existing state directory with loose permissions.
//
// sdk/java/.../fleet/StateStore.java ensure() returns as soon as the directory exists, so a TT_STATE_DIR
// created by the deployment (volume mount, Dockerfile mkdir, 0755/0775/0777) is never brought to 0700.
// Files are 0600, but in a group/world-writable directory another local user can rename files over
// them: state.json is trusted on start-up (kill=false, last_issued_seq lowered -> replay of an older
// signed policy, and "added_keys" become pinned policy signing keys WITHOUT their endorsement being
// re-verified, see TrafficTwin.loadPersisted/signingKeys), i.e. arbitrary policies are accepted.
// The .NET SDK chmods the directory on every write (StateStore.Ensure); Java and PHP do not.
//
// Run (exit 1 = vulnerable, 0 = fixed):
//   docker run --rm -v "$PWD":/repo:ro eclipse-temurin:17 sh -c 'javac -d /tmp/o -sourcepath /repo/sdk/java/sdk/src/main/java /repo/test/redteam/java/RtStateDirPerms.java && java -cp /tmp/o RtStateDirPerms'

import io.github.ivseb.traffictwin.fleet.StateStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

public final class RtStateDirPerms {
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("tt-rt-state");
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxrwxrwx")); // pre-created by the deployment
        StateStore s = new StateStore(dir);
        s.writeText("state.json", "{}");
        String d = PosixFilePermissions.toString(Files.getPosixFilePermissions(dir));
        String f = PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("state.json")));
        System.out.println("state dir " + d + ", state.json " + f);
        int code = 0;
        if (!f.equals("rw-------")) {
            System.out.println("VULNERABLE: state file is not 0600");
            code = 1;
        }
        if (!d.equals("rwx------")) {
            System.out.println("VULNERABLE: a pre-existing state directory keeps " + d + " (expected rwx------ or a refusal)");
            code = 1;
        }
        System.exit(code);
    }
}
