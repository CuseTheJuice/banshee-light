// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.MessageDigest;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

final class BansheeSecureFiles {
    private BansheeSecureFiles() {
    }

    static void ownerOnlyDir(Path dir) throws IOException {
        Files.createDirectories(dir);
        ownerOnly(dir);
    }

    static void ownerOnly(Path path) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            if(Files.isDirectory(path)) {
                perms.add(PosixFilePermission.OWNER_EXECUTE);
            }
            Files.setPosixFilePermissions(path, perms);
        } catch(UnsupportedOperationException | IOException e) {
            try {
                UserPrincipal owner = Files.getOwner(path);
                AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
                if(view == null) {
                    return;
                }
                AclEntry allow = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(EnumSet.of(
                                AclEntryPermission.READ_DATA,
                                AclEntryPermission.WRITE_DATA,
                                AclEntryPermission.APPEND_DATA,
                                AclEntryPermission.DELETE,
                                AclEntryPermission.READ_ACL,
                                AclEntryPermission.WRITE_ACL,
                                AclEntryPermission.READ_ATTRIBUTES,
                                AclEntryPermission.WRITE_ATTRIBUTES,
                                AclEntryPermission.READ_NAMED_ATTRS,
                                AclEntryPermission.WRITE_NAMED_ATTRS,
                                AclEntryPermission.DELETE_CHILD,
                                AclEntryPermission.EXECUTE,
                                AclEntryPermission.SYNCHRONIZE))
                        .build();
                view.setAcl(List.of(allow));
            } catch(Exception ignored) {
            }
        }
    }

    static boolean sameSha256(byte[] a, byte[] b) {
        if(a == null || b == null || a.length != b.length) {
            return false;
        }
        int diff = 0;
        for(int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch(Exception e) {
            return new byte[0];
        }
    }
}
