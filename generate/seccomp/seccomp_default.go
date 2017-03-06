package seccomp

import (
	"runtime"
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

func arches() []rspec.Arch {
	native := runtime.GOARCH

	switch native {
	case "amd64":
		return []rspec.Arch{rspec.ArchX86_64, rspec.ArchX86, rspec.ArchX32}
	case "arm64":
		return []rspec.Arch{rspec.ArchARM, rspec.ArchAARCH64}
	case "mips64":
		return []rspec.Arch{rspec.ArchMIPS, rspec.ArchMIPS64, rspec.ArchMIPS64N32}
	case "mips64n32":
		return []rspec.Arch{rspec.ArchMIPS, rspec.ArchMIPS64, rspec.ArchMIPS64N32}
	case "mipsel64":
		return []rspec.Arch{rspec.ArchMIPSEL, rspec.ArchMIPSEL64, rspec.ArchMIPSEL64N32}
	case "mipsel64n32":
		return []rspec.Arch{rspec.ArchMIPSEL, rspec.ArchMIPSEL64, rspec.ArchMIPSEL64N32}
	case "s390x":
		return []rspec.Arch{rspec.ArchS390, rspec.ArchS390X}
	default:
		return []rspec.Arch{}
	}
}

// DefaultProfile defines the whitelist for the default seccomp profile.
func DefaultProfile(rs *specs.Spec) *rspec.LinuxSeccomp {

	syscalls := []rspec.LinuxSyscall{
		{
			Names:  []string{"accept"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"accept4"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"access"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"alarm"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"bind"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"brk"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"capget"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"capset"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"chdir"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"chmod"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"chown"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"chown32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},

		{
			Names:  []string{"clock_getres"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"clock_gettime"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"clock_nanosleep"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"close"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"connect"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"copy_file_range"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"creat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"dup"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"dup2"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"dup3"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_create"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_create1"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_ctl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_ctl_old"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_pwait"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_wait"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"epoll_wait_old"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"eventfd"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"eventfd2"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"execve"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"execveat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"exit"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"exit_group"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"faccessat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fadvise64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fadvise64_64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fallocate"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fanotify_mark"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fchdir"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fchmod"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fchmodat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fchown"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fchown32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fchownat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fcntl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fcntl64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fdatasync"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fgetxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"flistxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"flock"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fork"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fremovexattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fsetxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fstat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fstat64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fstatat64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fstatfs"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fstatfs64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"fsync"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ftruncate"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ftruncate64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"futex"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"futimesat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getcpu"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getcwd"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getdents"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getdents64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getegid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getegid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"geteuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"geteuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getgid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getgroups"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getgroups32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getitimer"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getpeername"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getpgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getpgrp"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getpid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getppid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getpriority"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getrandom"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getresgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getresgid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getresuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getresuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getrlimit"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"get_robust_list"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getrusage"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getsid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getsockname"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getsockopt"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"get_thread_area"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"gettid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"gettimeofday"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"getxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"inotify_add_watch"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"inotify_init"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"inotify_init1"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"inotify_rm_watch"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"io_cancel"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ioctl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"io_destroy"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"io_getevents"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ioprio_get"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ioprio_set"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"io_setup"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"io_submit"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ipc"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"kill"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lchown"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lchown32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lgetxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"link"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"linkat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"listen"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"listxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"llistxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"_llseek"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lremovexattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lseek"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lsetxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lstat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"lstat64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"madvise"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"memfd_create"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mincore"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mkdir"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mkdirat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mknod"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mknodat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mlock"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mlock2"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mlockall"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mmap"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mmap2"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mprotect"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mq_getsetattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mq_notify"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mq_open"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mq_timedreceive"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mq_timedsend"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mq_unlink"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"mremap"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"msgctl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"msgget"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"msgrcv"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"msgsnd"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"msync"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"munlock"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"munlockall"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"munmap"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"nanosleep"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"newfstatat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"_newselect"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"open"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"openat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"pause"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"personality"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index: 0,
					Value: 0x0,
					Op:    rspec.OpEqualTo,
				},
			},
		},
		{
			Names:  []string{"personality"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index: 0,
					Value: 0x0008,
					Op:    rspec.OpEqualTo,
				},
			},
		},
		{
			Names:  []string{"personality"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index: 0,
					Value: 0xffffffff,
					Op:    rspec.OpEqualTo,
				},
			},
		},
		{
			Names:  []string{"pipe"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"pipe2"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"poll"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ppoll"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"prctl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"pread64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"preadv"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"prlimit64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"pselect6"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"pwrite64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"pwritev"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"read"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"readahead"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"readlink"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"readlinkat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"readv"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"recv"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"recvfrom"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"recvmmsg"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"recvmsg"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"remap_file_pages"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"removexattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rename"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"renameat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"renameat2"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"restart_syscall"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rmdir"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigaction"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigpending"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigprocmask"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigqueueinfo"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigreturn"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigsuspend"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_sigtimedwait"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"rt_tgsigqueueinfo"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_getaffinity"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_getattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_getparam"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_get_priority_max"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_get_priority_min"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_getscheduler"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_rr_get_interval"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_setaffinity"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_setattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_setparam"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_setscheduler"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sched_yield"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"seccomp"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"select"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"semctl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"semget"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"semop"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"semtimedop"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"send"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sendfile"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sendfile64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sendmmsg"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sendmsg"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sendto"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setfsgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setfsgid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setfsuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setfsuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setgid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setgroups"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setgroups32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setitimer"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setpgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setpriority"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setregid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setregid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setresgid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setresgid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setresuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setresuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setreuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setreuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setrlimit"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"set_robust_list"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setsid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setsockopt"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"set_thread_area"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"set_tid_address"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setuid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setuid32"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"setxattr"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"shmat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"shmctl"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"shmdt"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"shmget"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"shutdown"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sigaltstack"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"signalfd"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"signalfd4"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sigreturn"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"socket"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"socketcall"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"socketpair"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"splice"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"stat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"stat64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"statfs"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"statfs64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"symlink"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"symlinkat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sync"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sync_file_range"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"syncfs"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"sysinfo"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"syslog"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"tee"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"tgkill"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"time"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timer_create"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timer_delete"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timerfd_create"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timerfd_gettime"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timerfd_settime"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timer_getoverrun"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timer_gettime"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"timer_settime"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"times"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"tkill"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"truncate"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"truncate64"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"ugetrlimit"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"umask"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"uname"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"unlink"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"unlinkat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"utime"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"utimensat"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"utimes"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"vfork"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"vmsplice"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"wait4"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"waitid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"waitpid"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"write"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"writev"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
	}
	var sysCloneFlagsIndex uint

	capSysAdmin := false
	var cap string

	for _, cap = range rs.Process.Capabilities {
		switch cap {
		case "CAP_DAC_READ_SEARCH":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"open_by_handle_at"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_ADMIN":
			capSysAdmin = true
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"bpf"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"clone"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"fanotify_init"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"lookup_dcookie"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"mount"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"name_to_handle_at"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"perf_event_open"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"setdomainname"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"sethostname"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"setns"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"umount"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"umount2"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"unshare"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_BOOT":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"reboot"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_CHROOT":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"chroot"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_MODULE":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"delete_module"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"init_module"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"finit_module"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"query_module"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_PACCT":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"acct"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_PTRACE":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"kcmp"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"process_vm_readv"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"process_vm_writev"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"ptrace"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_RAWIO":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"iopl"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"ioperm"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_TIME":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"settimeofday"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"stime"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
				{
					Names:  []string{"adjtimex"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		case "CAP_SYS_TTY_CONFIG":
			syscalls = append(syscalls, []rspec.LinuxSyscall{
				{
					Names:  []string{"vhangup"},
					Action: rspec.ActAllow,
					Args:   []rspec.LinuxSeccompArg{},
				},
			}...)
		}
	}

	if !capSysAdmin {
		syscalls = append(syscalls, []rspec.LinuxSyscall{
			{
				Names:  []string{"clone"},
				Action: rspec.ActAllow,
				Args: []rspec.LinuxSeccompArg{
					{
						Index:    sysCloneFlagsIndex,
						Value:    syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET,
						ValueTwo: 0,
						Op:       rspec.OpMaskedEqual,
					},
				},
			},
		}...)

	}

	arch := runtime.GOARCH
	switch arch {
	case "arm", "arm64":
		syscalls = append(syscalls, []rspec.LinuxSyscall{
			{
				Names:  []string{"breakpoint"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
			{
				Names:  []string{"cacheflush"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
			{
				Names:  []string{"set_tls"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
		}...)
	case "amd64", "x32":
		syscalls = append(syscalls, []rspec.LinuxSyscall{
			{
				Names:  []string{"arch_prctl"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
		}...)
		fallthrough
	case "x86":
		syscalls = append(syscalls, []rspec.LinuxSyscall{
			{
				Names:  []string{"modify_ldt"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
		}...)
	case "s390", "s390x":
		syscalls = append(syscalls, []rspec.LinuxSyscall{
			{
				Names:  []string{"s390_pci_mmio_read"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
			{
				Names:  []string{"s390_pci_mmio_write"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
			{
				Names:  []string{"s390_runtime_instr"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
		}...)
		/* Flags parameter of the clone syscall is the 2nd on s390 */
	}

	return &rspec.LinuxSeccomp{
		DefaultAction: rspec.ActErrno,
		Architectures: arches(),
		Syscalls:      syscalls,
	}
}
