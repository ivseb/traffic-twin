package io.github.ivseb.traffictwin.fleet;

import io.github.ivseb.traffictwin.sanitizer.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.FileSystems;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Consumer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

/**
 * Local state of the source: enrollment, PKCS#12 with the client key, signed policy cache, kill
 * switch. Directory 0700, files 0600 (on POSIX file systems), atomic replace.
 *
 * <p>Trust (POSIX): the directory (and {@code ~/.traffic-twin}, the parent of the default one) is created 0700. A
 * pre-existing directory owned by another user is refused ({@link #prepare()} returns false, writes throw) and a
 * group/world-accessible one owned by us is repaired to 0700. A state file is read only when it is a regular
 * file (not a symlink) owned by the current user and not group/world-writable; otherwise it reads as absent
 * and the {@code onUntrusted} callback is told (never its contents). {@code keystore.pass} lives next to
 * {@code client.p12}: both are protected by the same 0700 directory and 0600 mode, not by the password
 * (set {@code TT_KEYSTORE_PASSWORD} to keep the password off the disk altogether).
 */
public final class StateStore {
    private static final Set<PosixFilePermission> PRIVATE = PosixFilePermissions.fromString("rwx------");
    private final Path dir;
    private final Consumer<String> onUntrusted;

    public StateStore(Path dir) {
        this(dir, null);
    }

    public StateStore(Path dir, Consumer<String> onUntrusted) {
        this.dir = dir;
        this.onUntrusted = onUntrusted;
    }

    public static Path defaultDir(String enrollUrl, String serviceName) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest((enrollUrl + "\0" + serviceName).getBytes(StandardCharsets.UTF_8));
            return Path.of(System.getProperty("user.home"), ".traffic-twin", HexFormat.of().formatHex(h).substring(0, 16));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public Path dir() {
        return dir;
    }

    /** Creates/validates the directory; false when it cannot be trusted (foreign owner, symlink, cannot be repaired). */
    public boolean prepare() {
        try {
            ensure();
            return true;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    private void ensure() throws IOException {
        Path parent = dir.getParent();
        if (parent != null && parent.getFileName() != null && parent.getFileName().toString().equals(".traffic-twin")) {
            makePrivate(parent); // the default layout: ~/.traffic-twin/<id>
        }
        makePrivate(dir);
    }

    private static void makePrivate(Path d) throws IOException {
        if (!Files.exists(d, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.createDirectories(d, PosixFilePermissions.asFileAttribute(PRIVATE));
            } catch (UnsupportedOperationException e) {
                Files.createDirectories(d);
                return;
            }
        }
        if (!Files.isDirectory(d)) throw new IOException("state_dir_not_a_directory");
        PosixFileAttributeView v = Files.getFileAttributeView(d, PosixFileAttributeView.class);
        if (v == null) return; // not a POSIX file system: nothing to check
        PosixFileAttributes a = v.readAttributes();
        if (!ownedByUs(a.owner())) throw new IOException("state_dir_foreign_owner");
        if (!a.permissions().equals(PRIVATE)) {
            Files.setPosixFilePermissions(d, PRIVATE);
            if (!Files.getPosixFilePermissions(d).equals(PRIVATE)) throw new IOException("state_dir_not_private");
        }
    }

    private static volatile UserPrincipal self;

    private static boolean ownedByUs(UserPrincipal owner) throws IOException {
        UserPrincipal me = self;
        if (me == null) {
            me = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
            self = me;
        }
        return me.equals(owner);
    }

    public byte[] readBytes(String name) {
        Path p = dir.resolve(name);
        try {
            PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            boolean ok = a.isRegularFile() && ownedByUs(a.owner())
                && !a.permissions().contains(PosixFilePermission.GROUP_WRITE) && !a.permissions().contains(PosixFilePermission.OTHERS_WRITE);
            if (ok && (name.equals("client.p12") || name.equals("keystore.pass"))) {
                if (!Collections.disjoint(a.permissions(), LOOSE_READ)) {
                    try {
                        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------")); // ours: tighten
                    } catch (IOException e) {
                        ok = false;
                    }
                }
            }
            if (!ok) {
                if (onUntrusted != null) onUntrusted.accept("state_file_untrusted");
                return null;
            }
        } catch (UnsupportedOperationException e) {
            // not POSIX: no ownership information
        } catch (IOException e) {
            return null;
        }
        try {
            return Files.readAllBytes(p);
        } catch (IOException e) {
            return null;
        }
    }

    private static final Set<PosixFilePermission> LOOSE_READ = EnumSet.of(PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);

    public String readText(String name) {
        byte[] b = readBytes(name);
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> readJson(String name) {
        byte[] b = readBytes(name);
        if (b == null) return null;
        try {
            Object o = Json.parsePlain(b, false);
            return o instanceof Map<?, ?> ? (Map<String, Object>) o : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Atomic write; the file is created with mode 0600 before any byte is written. */
    public void writeBytes(String name, byte[] data) throws IOException {
        ensure();
        Path tmp = dir.resolve("." + name + "." + ProcessHandle.current().pid() + ".tmp");
        Files.deleteIfExists(tmp);
        try {
            Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            Files.createFile(tmp);
        }
        Files.write(tmp, data);
        try {
            Files.move(tmp, dir.resolve(name), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, dir.resolve(name), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public void writeText(String name, String text) throws IOException {
        writeBytes(name, text.getBytes(StandardCharsets.UTF_8));
    }

    public void writeJson(String name, Map<String, Object> value) throws IOException {
        writeText(name, Json.writeCanonical(value));
    }

    public void remove(String name) {
        try {
            Files.deleteIfExists(dir.resolve(name));
        } catch (IOException e) {
            // best effort
        }
    }
}
