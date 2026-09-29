"""Derive infra/seccomp/doubleblind.json from Docker's default seccomp profile.

Docker's default profile is already an allowlist (default action ERRNO). We
tighten it further by removing syscalls that no DOUBLE-BLIND zone needs and
that are classic cross-process / cross-container inspection or escape
primitives. Re-run after updating the upstream profile:

    curl -sSLo /tmp/default.json https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json
    python infra/seccomp/build_profile.py /tmp/default.json infra/seccomp/doubleblind.json
"""

import json
import sys

REMOVE = {
    # inspecting / manipulating other processes
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd", "pidfd_open",
    # handle-based file access that can bypass path-based confinement
    "name_to_handle_at", "open_by_handle_at",
    # kernel attack surface a Python web service never needs
    "bpf", "perf_event_open", "userfaultfd", "io_uring_setup", "io_uring_enter", "io_uring_register",
    "keyctl", "add_key", "request_key", "lookup_dcookie", "fanotify_init",
    # namespace / mount manipulation (also cap-gated upstream; removed outright here)
    "unshare", "setns", "mount", "umount", "umount2", "pivot_root", "chroot", "open_tree", "move_mount",
    "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
    # host-level administration
    "acct", "quotactl", "syslog", "vhangup", "swapon", "swapoff", "reboot", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
}


def main(src: str, dst: str) -> None:
    prof = json.load(open(src))
    removed = set()
    kept = []
    for rule in prof["syscalls"]:
        if rule["action"] == "SCMP_ACT_ALLOW":
            names = [n for n in rule["names"] if n not in REMOVE]
            removed |= set(rule["names"]) - set(names)
            if not names:
                continue
            rule = {**rule, "names": names}
        kept.append(rule)
    prof["syscalls"] = kept
    json.dump(prof, open(dst, "w"), indent=1)
    allowed = sum(len(r["names"]) for r in kept if r["action"] == "SCMP_ACT_ALLOW")
    print(f"removed {len(removed)} syscalls from the allowlist: {sorted(removed)}")
    print(f"{allowed} syscall names remain allowed (default action {prof['defaultAction']})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
