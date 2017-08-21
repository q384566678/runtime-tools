package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/opencontainers/runtime-tools/generate/seccomp"
	"github.com/urfave/cli"
)

var generateFlags = []cli.Flag{
	cli.StringSliceFlag{Name: "args", Usage: "command to run in the container"},
	cli.StringSliceFlag{Name: "env", Usage: "add environment variable e.g. key=value"},
	cli.StringSliceFlag{Name: "env-file", Usage: "read in a file of environment variables"},
	cli.StringSliceFlag{Name: "hooks-poststart", Usage: "set command to run in poststart hooks"},
	cli.StringSliceFlag{Name: "hooks-poststart-env", Usage: "set environment variables for commands to run in poststart hooks"},
	cli.StringSliceFlag{Name: "hooks-poststart-timeout", Usage: "set timeout for commands to run in poststart hooks"},
	cli.StringSliceFlag{Name: "hooks-poststop", Usage: "set command to run in poststop hooks"},
	cli.StringSliceFlag{Name: "hooks-poststop-env", Usage: "set environment variables for commands to run in poststop hooks"},
	cli.StringSliceFlag{Name: "hooks-poststop-timeout", Usage: "set timeout for commands to run in poststop hooks"},
	cli.StringSliceFlag{Name: "hooks-prestart", Usage: "set command to run in prestart hooks"},
	cli.StringSliceFlag{Name: "hooks-prestart-env", Usage: "set environment variables for commands to run in prestart hooks"},
	cli.StringSliceFlag{Name: "hooks-prestart-timeout", Usage: "set timeout for commands to run in prestart hooks"},
	cli.StringFlag{Name: "hostname", Usage: "hostname value for the container"},
	cli.StringSliceFlag{Name: "label", Usage: "add annotations to the configuration e.g. key=value"},
	cli.StringFlag{Name: "linux-apparmor", Usage: "specifies the the apparmor profile for the container"},
	cli.StringFlag{Name: "linux-cgroups-path", Usage: "specify the path to the cgroups"},
	cli.Uint64Flag{Name: "linux-cpu-period", Usage: "the CPU period to be used for hardcapping (in usecs)"},
	cli.Uint64Flag{Name: "linux-cpu-quota", Usage: "the allowed CPU time in a given period (in usecs)"},
	cli.Uint64Flag{Name: "linux-cpu-shares", Usage: "the relative share of CPU time available to the tasks in a cgroup"},
	cli.StringFlag{Name: "linux-cpus", Usage: "CPUs to use within the cpuset (default is to use any CPU available)"},
	cli.StringSliceFlag{Name: "linux-device-add", Usage: "add a device which must be made available in the container"},
	cli.StringSliceFlag{Name: "linux-device-remove", Usage: "remove a device which must be made available in the container"},
	cli.BoolFlag{Name: "linux-device-remove-all", Usage: "remove all devices which must be made available in the container"},
	cli.BoolFlag{Name: "linux-disable-oom-kill", Usage: "disable OOM Killer"},
	cli.StringSliceFlag{Name: "linux-gidmappings", Usage: "add GIDMappings e.g HostID:ContainerID:Size"},
	cli.StringSliceFlag{Name: "linux-hugepage-limits-add", Usage: "add hugepage resource limits"},
	cli.StringSliceFlag{Name: "linux-hugepage-limits-drop", Usage: "drop hugepage resource limits"},
	cli.StringSliceFlag{Name: "linux-masked-paths", Usage: "specifies paths can not be read inside container"},
	cli.Uint64Flag{Name: "linux-mem-kernel-limit", Usage: "kernel memory limit (in bytes)"},
	cli.Uint64Flag{Name: "linux-mem-kernel-tcp", Usage: "kernel memory limit for tcp (in bytes)"},
	cli.Uint64Flag{Name: "linux-mem-limit", Usage: "memory limit (in bytes)"},
	cli.Uint64Flag{Name: "linux-mem-reservation", Usage: "memory reservation or soft limit (in bytes)"},
	cli.StringFlag{Name: "linux-mems", Usage: "list of memory nodes in the cpuset (default is to use any available memory node)"},
	cli.Uint64Flag{Name: "linux-mem-swap", Usage: "total memory limit (memory + swap) (in bytes)"},
	cli.Uint64Flag{Name: "linux-mem-swappiness", Usage: "how aggressive the kernel will swap memory pages (Range from 0 to 100)"},
	cli.StringFlag{Name: "linux-mount-label", Usage: "selinux mount context label"},
	cli.StringSliceFlag{Name: "linux-namespace-add", Usage: "adds a namespace to the set of namespaces to create or join of the form 'ns[:path]'"},
	cli.StringSliceFlag{Name: "linux-namespace-remove", Usage: "removes a namespace from the set of namespaces to create or join of the form 'ns'"},
	cli.BoolFlag{Name: "linux-namespace-remove-all", Usage: "removes all namespaces from the set of namespaces created or joined"},
	cli.IntFlag{Name: "linux-network-classid", Usage: "specifies class identifier tagged by container's network packets"},
	cli.StringSliceFlag{Name: "linux-network-priorities", Usage: "specifies priorities of network traffic"},
	cli.IntFlag{Name: "linux-oom-score-adj", Usage: "oom_score_adj for the container"},
	cli.Int64Flag{Name: "linux-pids-limit", Usage: "maximum number of PIDs"},
	cli.StringSliceFlag{Name: "linux-readonly-paths", Usage: "specifies paths readonly inside container"},
	cli.Int64Flag{Name: "linux-realtime-period", Usage: "CPU period to be used for realtime scheduling (in usecs)"},
	cli.Int64Flag{Name: "linux-realtime-runtime", Usage: "the time realtime scheduling may use (in usecs)"},
	cli.StringSliceFlag{Name: "linux-resources-device-add", Usage: "add a device access rule"},
	cli.StringSliceFlag{Name: "linux-resources-device-remove", Usage: "remove a device access rule"},
	cli.StringFlag{Name: "linux-rootfs-propagation", Usage: "mount propagation for rootfs"},
	cli.StringFlag{Name: "linux-seccomp-allow", Usage: "specifies syscalls to respond with allow"},
	cli.StringFlag{Name: "linux-seccomp-arch", Usage: "specifies additional architectures permitted to be used for system calls"},
	cli.StringFlag{Name: "linux-seccomp-default", Usage: "specifies default action to be used for system calls and removes existing rules with specified action"},
	cli.StringFlag{Name: "linux-seccomp-default-force", Usage: "same as seccomp-default but does not remove existing rules with specified action"},
	cli.StringFlag{Name: "linux-seccomp-errno", Usage: "specifies syscalls to respond with errno"},
	cli.StringFlag{Name: "linux-seccomp-kill", Usage: "specifies syscalls to respond with kill"},
	cli.BoolFlag{Name: "linux-seccomp-only", Usage: "specifies to export just a seccomp configuration file"},
	cli.StringFlag{Name: "linux-seccomp-remove", Usage: "specifies syscalls to remove seccomp rules for"},
	cli.BoolFlag{Name: "linux-seccomp-remove-all", Usage: "removes all syscall rules from seccomp configuration"},
	cli.StringFlag{Name: "linux-seccomp-trace", Usage: "specifies syscalls to respond with trace"},
	cli.StringFlag{Name: "linux-seccomp-trap", Usage: "specifies syscalls to respond with trap"},
	cli.StringFlag{Name: "linux-selinux-label", Usage: "process selinux label"},
	cli.StringSliceFlag{Name: "linux-sysctl", Usage: "add sysctl settings e.g net.ipv4.forward=1"},
	cli.StringSliceFlag{Name: "linux-uidmappings", Usage: "add UIDMappings e.g HostID:ContainerID:Size"},
	cli.StringSliceFlag{Name: "mount-bind", Usage: "bind mount directories src:dest[:options...]"},
	cli.StringFlag{Name: "mount-cgroups", Value: "no", Usage: "mount cgroups (rw,ro,no)"},
	cli.StringFlag{Name: "output", Usage: "output file (defaults to stdout)"},
	cli.BoolFlag{Name: "privileged", Usage: "enable privileged container settings"},
	cli.StringSliceFlag{Name: "process-cap-add", Usage: "add Linux capabilities"},
	cli.StringSliceFlag{Name: "process-cap-drop", Usage: "drop Linux capabilities"},
	cli.BoolFlag{Name: "process-cap-drop-all", Usage: "drop all Linux capabilities"},
	cli.StringFlag{Name: "process-consolesize", Usage: "specifies the console size in characters (width:height)"},
	cli.StringFlag{Name: "process-cwd", Value: "/", Usage: "current working directory for the process"},
	cli.IntFlag{Name: "process-gid", Usage: "gid for the process"},
	cli.StringSliceFlag{Name: "process-groups", Usage: "supplementary groups for the process"},
	cli.BoolFlag{Name: "process-no-new-privileges", Usage: "set no new privileges bit for the container process"},
	cli.StringSliceFlag{Name: "process-rlimits-add", Usage: "specifies resource limits for processes inside the container. "},
	cli.StringSliceFlag{Name: "process-rlimits-remove", Usage: "remove specified resource limits for processes inside the container. "},
	cli.BoolFlag{Name: "process-rlimits-remove-all", Usage: "remove all resource limits for processes inside the container. "},
	cli.BoolFlag{Name: "process-tty", Usage: "allocate a new tty for the container process"},
	cli.IntFlag{Name: "process-uid", Usage: "uid for the process"},
	cli.StringFlag{Name: "rootfs-path", Value: "rootfs", Usage: "path to the root filesystem"},
	cli.BoolFlag{Name: "rootfs-readonly", Usage: "make the container's rootfs readonly"},
	cli.StringFlag{Name: "template", Usage: "base template to use for creating the configuration"},
	cli.StringSliceFlag{Name: "tmpfs", Usage: "mount tmpfs e.g. ContainerDIR[:OPTIONS...]"},
}

var generateCommand = cli.Command{
	Name:   "generate",
	Usage:  "generate an OCI spec file",
	Flags:  generateFlags,
	Before: before,
	Action: func(context *cli.Context) error {
		// Start from the default template.
		specgen := generate.New()

		var template string
		if context.IsSet("template") {
			template = context.String("template")
		}
		if template != "" {
			var err error
			specgen, err = generate.NewFromFile(template)
			if err != nil {
				return err
			}
		}

		err := setupSpec(&specgen, context)
		if err != nil {
			return err
		}

		var exportOpts generate.ExportOptions
		exportOpts.Seccomp = context.Bool("linux-seccomp-only")

		if context.IsSet("output") {
			err = specgen.SaveToFile(context.String("output"), exportOpts)
		} else {
			err = specgen.Save(os.Stdout, exportOpts)
		}
		if err != nil {
			return err
		}
		return nil
	},
}

func setupSpec(g *generate.Generator, context *cli.Context) error {
	if context.GlobalBool("host-specific") {
		g.HostSpecific = true
	}

	spec := g.Spec()

	if len(spec.Version) == 0 {
		g.SetVersion(rspec.Version)
	}

	if context.IsSet("hostname") {
		g.SetHostname(context.String("hostname"))
	}

	if context.IsSet("label") {
		annotations := context.StringSlice("label")
		for _, s := range annotations {
			pair := strings.SplitN(s, "=", 2)
			if len(pair) != 2 || pair[0] == "" {
				return fmt.Errorf("incorrectly specified annotation: %s", s)
			}
			g.AddAnnotation(pair[0], pair[1])
		}
	}

	g.SetRootPath(context.String("rootfs-path"))

	if context.IsSet("rootfs-readonly") {
		g.SetRootReadonly(context.Bool("rootfs-readonly"))
	}

	if context.IsSet("process-uid") {
		g.SetProcessUID(uint32(context.Int("process-uid")))
	}

	if context.IsSet("process-gid") {
		g.SetProcessGID(uint32(context.Int("process-gid")))
	}

	if context.IsSet("linux-selinux-label") {
		g.SetProcessSelinuxLabel(context.String("linux-selinux-label"))
	}

	g.SetProcessCwd(context.String("process-cwd"))

	if context.IsSet("linux-apparmor") {
		g.SetProcessApparmorProfile(context.String("linux-apparmor"))
	}

	if context.IsSet("process-no-new-privileges") {
		g.SetProcessNoNewPrivileges(context.Bool("process-no-new-privileges"))
	}

	if context.IsSet("process-tty") {
		g.SetProcessTerminal(context.Bool("process-tty"))
	}

	if context.IsSet("args") {
		g.SetProcessArgs(context.StringSlice("args"))
	}

	{
		envs, err := readKVStrings(context.StringSlice("env-file"), context.StringSlice("env"))
		if err != nil {
			return err
		}

		for _, env := range envs {
			name, value, err := parseEnv(env)
			if err != nil {
				return err
			}
			g.AddProcessEnv(name, value)
		}
	}

	if context.IsSet("process-groups") {
		groups := context.StringSlice("process-groups")
		for _, group := range groups {
			groupID, err := strconv.Atoi(group)
			if err != nil {
				return err
			}
			g.AddProcessAdditionalGid(uint32(groupID))
		}
	}

	if context.IsSet("linux-cgroups-path") {
		g.SetLinuxCgroupsPath(context.String("linux-cgroups-path"))
	}

	if context.IsSet("linux-masked-paths") {
		paths := context.StringSlice("linux-masked-paths")
		for _, path := range paths {
			g.AddLinuxMaskedPaths(path)
		}
	}

	if context.IsSet("linux-resources-device-add") {
		devices := context.StringSlice("linux-resources-device-add")
		for _, device := range devices {
			dev, err := parseLinuxResourcesDeviceAccess(device, g)
			if err != nil {
				return err
			}
			g.AddLinuxResourcesDevice(dev.Allow, dev.Type, dev.Major, dev.Minor, dev.Access)
		}
	}

	if context.IsSet("linux-resources-device-remove") {
		devices := context.StringSlice("linux-resources-device-remove")
		for _, device := range devices {
			dev, err := parseLinuxResourcesDeviceAccess(device, g)
			if err != nil {
				return err
			}
			g.RemoveLinuxResourcesDevice(dev.Allow, dev.Type, dev.Major, dev.Minor, dev.Access)
		}
	}

	if context.IsSet("linux-readonly-paths") {
		paths := context.StringSlice("linux-readonly-paths")
		for _, path := range paths {
			g.AddLinuxReadonlyPaths(path)
		}
	}

	if context.IsSet("linux-mount-label") {
		g.SetLinuxMountLabel(context.String("linux-mount-label"))
	}

	if context.IsSet("linux-sysctl") {
		sysctls := context.StringSlice("linux-sysctl")
		for _, s := range sysctls {
			pair := strings.Split(s, "=")
			if len(pair) != 2 {
				return fmt.Errorf("incorrectly specified sysctl: %s", s)
			}
			g.AddLinuxSysctl(pair[0], pair[1])
		}
	}

	g.SetupPrivileged(context.Bool("privileged"))

	if context.IsSet("process-cap-add") {
		addCaps := context.StringSlice("process-cap-add")
		for _, cap := range addCaps {
			if err := g.AddProcessCapability(cap); err != nil {
				return err
			}
		}
	}

	if context.IsSet("process-cap-drop") {
		dropCaps := context.StringSlice("process-cap-drop")
		for _, cap := range dropCaps {
			if err := g.DropProcessCapability(cap); err != nil {
				return err
			}
		}
	}

	if context.IsSet("process-consolesize") {
		consoleSize := context.String("process-consolesize")
		width, height, err := parseConsoleSize(consoleSize)
		if err != nil {
			return err
		}
		g.SetProcessConsoleSize(width, height)
	}

	if context.Bool("process-cap-drop-all") {
		g.ClearProcessCapabilities()
	}

	var uidMaps, gidMaps []string

	if context.IsSet("linux-uidmappings") {
		uidMaps = context.StringSlice("linux-uidmappings")
	}

	if context.IsSet("linux-gidmappings") {
		gidMaps = context.StringSlice("linux-gidmappings")
	}

	// Add default user namespace.
	if len(uidMaps) > 0 || len(gidMaps) > 0 {
		g.AddOrReplaceLinuxNamespace("user", "")
	}

	if context.IsSet("tmpfs") {
		tmpfsSlice := context.StringSlice("tmpfs")
		for _, s := range tmpfsSlice {
			dest, options, err := parseTmpfsMount(s)
			if err != nil {
				return err
			}
			g.AddTmpfsMount(dest, options)
		}
	}

	mountCgroupOption := context.String("mount-cgroups")
	if err := g.AddCgroupsMount(mountCgroupOption); err != nil {
		return err
	}

	if context.IsSet("mount-bind") {
		binds := context.StringSlice("mount-bind")
		for _, bind := range binds {
			source, dest, options, err := parseBindMount(bind)
			if err != nil {
				return err
			}
			g.AddBindMount(source, dest, options)
		}
	}

	if context.IsSet("hooks-poststart") {
		postStartHooks := context.StringSlice("hooks-poststart")
		for _, hook := range postStartHooks {
			path, args, err := parseHook(hook)
			if err != nil {
				return err
			}
			g.AddPostStartHook(path, args)
		}
	}

	if context.IsSet("hooks-poststart-env") {
		postStartEnvs := context.StringSlice("hooks-poststart-env")
		for _, postStartEnv := range postStartEnvs {
			path, env, err := parseHookEnv(postStartEnv)
			if err != nil {
				return err
			}
			g.AddPostStartHookEnv(path, env)
		}
	}

	if context.IsSet("hooks-poststart-timeout") {
		postStartTimeouts := context.StringSlice("hooks-poststart-timeout")
		for _, postStartTimeout := range postStartTimeouts {
			path, timeout, err := parseHookTimeout(postStartTimeout)
			if err != nil {
				return err
			}
			g.AddPostStartHookTimeout(path, timeout)
		}
	}

	if context.IsSet("hooks-poststop") {
		postStopHooks := context.StringSlice("hooks-poststop")
		for _, hook := range postStopHooks {
			path, args, err := parseHook(hook)
			if err != nil {
				return err
			}
			g.AddPostStopHook(path, args)
		}
	}

	if context.IsSet("hooks-poststop-env") {
		postStopEnvs := context.StringSlice("hooks-poststop-env")
		for _, postStopEnv := range postStopEnvs {
			path, env, err := parseHookEnv(postStopEnv)
			if err != nil {
				return err
			}
			g.AddPostStopHookEnv(path, env)
		}
	}

	if context.IsSet("hooks-poststop-timeout") {
		postStopTimeouts := context.StringSlice("hooks-poststop-timeout")
		for _, postStopTimeout := range postStopTimeouts {
			path, timeout, err := parseHookTimeout(postStopTimeout)
			if err != nil {
				return err
			}
			g.AddPostStopHookTimeout(path, timeout)
		}
	}

	if context.IsSet("hooks-prestart") {
		preStartHooks := context.StringSlice("hooks-prestart")
		for _, hook := range preStartHooks {
			path, args, err := parseHook(hook)
			if err != nil {
				return err
			}
			g.AddPreStartHook(path, args)
		}
	}

	if context.IsSet("hooks-prestart-env") {
		preStartEnvs := context.StringSlice("hooks-prestart-env")
		for _, preStartEnv := range preStartEnvs {
			path, env, err := parseHookEnv(preStartEnv)
			if err != nil {
				return err
			}
			g.AddPreStartHookEnv(path, env)
		}
	}

	if context.IsSet("hooks-prestart-timeout") {
		preStartTimeouts := context.StringSlice("hooks-prestart-timeout")
		for _, preStartTimeout := range preStartTimeouts {
			path, timeout, err := parseHookTimeout(preStartTimeout)
			if err != nil {
				return err
			}
			g.AddPreStartHookTimeout(path, timeout)
		}
	}

	if context.IsSet("linux-rootfs-propagation") {
		rp := context.String("linux-rootfs-propagation")
		if err := g.SetLinuxRootPropagation(rp); err != nil {
			return err
		}
	}

	for _, uidMap := range uidMaps {
		hid, cid, size, err := parseIDMapping(uidMap)
		if err != nil {
			return err
		}

		g.AddLinuxUIDMapping(hid, cid, size)
	}

	for _, gidMap := range gidMaps {
		hid, cid, size, err := parseIDMapping(gidMap)
		if err != nil {
			return err
		}

		g.AddLinuxGIDMapping(hid, cid, size)
	}

	if context.IsSet("linux-disable-oom-kill") {
		g.SetLinuxResourcesMemoryDisableOOMKiller(context.Bool("linux-disable-oom-kill"))
	}

	if context.IsSet("linux-oom-score-adj") {
		g.SetProcessOOMScoreAdj(context.Int("linux-oom-score-adj"))
	}

	if context.IsSet("linux-cpu-shares") {
		g.SetLinuxResourcesCPUShares(context.Uint64("linux-cpu-shares"))
	}

	if context.IsSet("linux-cpu-period") {
		g.SetLinuxResourcesCPUPeriod(context.Uint64("linux-cpu-period"))
	}

	if context.IsSet("linux-cpu-quota") {
		g.SetLinuxResourcesCPUQuota(context.Int64("linux-cpu-quota"))
	}

	if context.IsSet("linux-realtime-runtime") {
		g.SetLinuxResourcesCPURealtimeRuntime(context.Int64("linux-realtime-runtime"))
	}

	if context.IsSet("linux-pids-limit") {
		g.SetLinuxResourcesPidsLimit(context.Int64("linux-pids-limit"))
	}

	if context.IsSet("linux-realtime-period") {
		g.SetLinuxResourcesCPURealtimePeriod(context.Uint64("linux-realtime-period"))
	}

	if context.IsSet("linux-cpus") {
		g.SetLinuxResourcesCPUCpus(context.String("linux-cpus"))
	}

	if context.IsSet("linux-hugepage-limits-add") {
		pageList := context.StringSlice("linux-hugepage-limits-add")
		for _, v := range pageList {
			pagesize, limit, err := parseHugepageLimit(v)
			if err != nil {
				return err
			}
			g.AddLinuxResourcesHugepageLimit(pagesize, limit)
		}
	}

	if context.IsSet("linux-hugepage-limits-drop") {
		pageList := context.StringSlice("linux-hugepage-limits-drop")
		for _, v := range pageList {
			g.DropLinuxResourcesHugepageLimit(v)
		}
	}

	if context.IsSet("linux-mems") {
		g.SetLinuxResourcesCPUMems(context.String("linux-mems"))
	}

	if context.IsSet("linux-mem-limit") {
		g.SetLinuxResourcesMemoryLimit(context.Int64("linux-mem-limit"))
	}

	if context.IsSet("linux-mem-reservation") {
		g.SetLinuxResourcesMemoryReservation(context.Int64("linux-mem-reservation"))
	}

	if context.IsSet("linux-mem-swap") {
		g.SetLinuxResourcesMemorySwap(context.Int64("linux-mem-swap"))
	}

	if context.IsSet("linux-mem-kernel-limit") {
		g.SetLinuxResourcesMemoryKernel(context.Int64("linux-mem-kernel-limit"))
	}

	if context.IsSet("linux-mem-kernel-tcp") {
		g.SetLinuxResourcesMemoryKernelTCP(context.Int64("linux-mem-kernel-tcp"))
	}

	if context.IsSet("linux-mem-swappiness") {
		g.SetLinuxResourcesMemorySwappiness(context.Uint64("linux-mem-swappiness"))
	}

	if context.IsSet("linux-network-classid") {
		g.SetLinuxResourcesNetworkClassID(uint32(context.Int("linux-network-classid")))
	}

	if context.IsSet("linux-network-priorities") {
		priorities := context.StringSlice("linux-network-priorities")
		for _, p := range priorities {
			name, priority, err := parseNetworkPriority(p)
			if err != nil {
				return err
			}
			if priority == -1 {
				g.DropLinuxResourcesNetworkPriorities(name)
			} else {
				g.AddLinuxResourcesNetworkPriorities(name, uint32(priority))
			}
		}
	}

	if context.IsSet("linux-namespace-add") {
		namespaces := context.StringSlice("linux-namespace-add")
		for _, ns := range namespaces {
			name, path, err := parseNamespace(ns)
			if err != nil {
				return err
			}
			if err := g.AddOrReplaceLinuxNamespace(name, path); err != nil {
				return err
			}
		}
	}

	if context.IsSet("linux-namespace-remove") {
		namespaces := context.StringSlice("linux-namespace-remove")
		for _, name := range namespaces {
			if err := g.RemoveLinuxNamespace(name); err != nil {
				return err
			}
		}
	}

	if context.Bool("linux-namespace-remove-all") {
		g.ClearLinuxNamespaces()
	}

	if context.IsSet("process-rlimits-add") {
		rlimits := context.StringSlice("process-rlimits-add")
		for _, rlimit := range rlimits {
			rType, rHard, rSoft, err := parseRlimit(rlimit)
			if err != nil {
				return err
			}
			g.AddProcessRlimits(rType, rHard, rSoft)
		}
	}

	if context.IsSet("process-rlimits-remove") {
		rlimits := context.StringSlice("process-rlimits-remove")
		for _, rlimit := range rlimits {
			err := g.RemoveProcessRlimits(rlimit)
			if err != nil {
				return err
			}
		}
	}

	if context.Bool("process-rlimits-remove-all") {
		g.ClearProcessRlimits()
	}

	if context.IsSet("linux-device-add") {
		devices := context.StringSlice("linux-device-add")
		for _, deviceArg := range devices {
			dev, err := parseDevice(deviceArg, g)
			if err != nil {
				return err
			}
			g.AddDevice(dev)
		}
	}

	if context.IsSet("linux-device-remove") {
		devices := context.StringSlice("linux-device-remove")
		for _, device := range devices {
			err := g.RemoveDevice(device)
			if err != nil {
				return err
			}
		}
	}

	if context.Bool("linux-device-remove-all") {
		g.ClearLinuxDevices()
	}

	err := addSeccomp(context, g)
	return err
}

func parseConsoleSize(consoleSize string) (uint, uint, error) {
	size := strings.Split(consoleSize, ":")
	if len(size) != 2 {
		return 0, 0, fmt.Errorf("invalid consolesize value: %s", consoleSize)
	}

	width, err := strconv.Atoi(size[0])
	if err != nil {
		return 0, 0, err
	}

	height, err := strconv.Atoi(size[1])
	if err != nil {
		return 0, 0, err
	}

	return uint(width), uint(height), nil
}

func parseIDMapping(idms string) (uint32, uint32, uint32, error) {
	idm := strings.Split(idms, ":")
	if len(idm) != 3 {
		return 0, 0, 0, fmt.Errorf("idmappings error: %s", idms)
	}

	hid, err := strconv.Atoi(idm[0])
	if err != nil {
		return 0, 0, 0, err
	}

	cid, err := strconv.Atoi(idm[1])
	if err != nil {
		return 0, 0, 0, err
	}

	size, err := strconv.Atoi(idm[2])
	if err != nil {
		return 0, 0, 0, err
	}

	return uint32(hid), uint32(cid), uint32(size), nil
}

func parseHugepageLimit(pageLimit string) (string, uint64, error) {
	pl := strings.Split(pageLimit, ":")
	if len(pl) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", pageLimit)
	}

	limit, err := strconv.Atoi(pl[1])
	if err != nil {
		return "", 0, err
	}

	return pl[0], uint64(limit), nil
}

func parseHook(s string) (string, []string, error) {
	args := []string{}
	parts := strings.Split(s, ":")
	if len(parts) > 1 && parts[0] == "" {
		return "", args, fmt.Errorf("invalid hook value: %s", s)
	}
	path := parts[0]
	if len(parts) > 1 {
		args = parts[1:]
	}
	return path, args, nil
}

func parseHookEnv(s string) (string, []string, error) {
	parts := strings.Split(s, ":")
	envs := []string{}
	if len(parts) < 2 {
		return "", envs, fmt.Errorf("invalid format: %s", s)
	}
	envs = parts[1:]

	return parts[0], envs, nil
}

func parseHookTimeout(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}

	timeout, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, err
	}

	return parts[0], timeout, nil
}

func parseNetworkPriority(np string) (string, int32, error) {
	var err error

	parts := strings.Split(np, ":")
	if len(parts) != 2 || parts[0] == "" {
		return "", 0, fmt.Errorf("invalid value %v for --linux-network-priorities", np)
	}
	priority, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, err
	}

	return parts[0], int32(priority), nil
}

func parseTmpfsMount(s string) (string, []string, error) {
	var dest string
	var options []string
	var err error

	parts := strings.Split(s, ":")
	if len(parts) == 2 && parts[0] != "" {
		dest = parts[0]
		options = strings.Split(parts[1], ",")
	} else if len(parts) == 1 {
		dest = parts[0]
		options = []string{"rw", "noexec", "nosuid", "nodev", "size=65536k"}
	} else {
		err = fmt.Errorf("invalid -- tmpfs value: %s", s)
	}

	return dest, options, err
}

func parseBindMount(s string) (string, string, []string, error) {
	var source, dest string
	options := []string{}

	bparts := strings.SplitN(s, ":", 3)
	switch len(bparts) {
	case 2:
		source, dest = bparts[0], bparts[1]
	case 3:
		source, dest, options = bparts[0], bparts[1], strings.Split(bparts[2], ":")
	default:
		return source, dest, options, fmt.Errorf("--mount-bind should have format src:dest[:options...]")
	}

	if source == "" || dest == "" {
		return source, dest, options, fmt.Errorf("--mount-bind should have format src:dest[:options...]")
	}
	return source, dest, options, nil
}

func parseRlimit(rlimit string) (string, uint64, uint64, error) {
	parts := strings.Split(rlimit, ":")
	if len(parts) != 3 || parts[0] == "" {
		return "", 0, 0, fmt.Errorf("invalid rlimits value: %s", rlimit)
	}

	hard, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, 0, err
	}

	soft, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", 0, 0, err
	}

	return parts[0], uint64(hard), uint64(soft), nil
}

func parseNamespace(ns string) (string, string, error) {
	parts := strings.SplitN(ns, ":", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", "", fmt.Errorf("invalid namespace value: %s", ns)
	}

	nsType := parts[0]
	nsPath := ""

	if len(parts) == 2 {
		nsPath = parts[1]
	}

	return nsType, nsPath, nil
}

var deviceType = map[string]bool{
	"b": true, // a block (buffered) special file
	"c": true, // a character special file
	"u": true, // a character (unbuffered) special file
	"p": true, // a FIFO
}

// parseDevice takes the raw string passed with the --device-add flag
func parseDevice(device string, g *generate.Generator) (rspec.LinuxDevice, error) {
	dev := rspec.LinuxDevice{}

	// The required part and optional part are separated by ":"
	argsParts := strings.Split(device, ":")
	if len(argsParts) < 4 {
		return dev, fmt.Errorf("Incomplete device arguments: %s", device)
	}
	requiredPart := argsParts[0:4]
	optionalPart := argsParts[4:]

	// The required part must contain type, major, minor, and path
	dev.Type = requiredPart[0]
	if !deviceType[dev.Type] {
		return dev, fmt.Errorf("Invalid device type: %s", dev.Type)
	}

	i, err := strconv.ParseInt(requiredPart[1], 10, 64)
	if err != nil {
		return dev, err
	}
	dev.Major = i

	i, err = strconv.ParseInt(requiredPart[2], 10, 64)
	if err != nil {
		return dev, err
	}
	dev.Minor = i
	dev.Path = requiredPart[3]

	// The optional part include all optional property
	for _, s := range optionalPart {
		parts := strings.SplitN(s, "=", 2)

		if len(parts) != 2 {
			return dev, fmt.Errorf("Incomplete device arguments: %s", s)
		}

		name, value := parts[0], parts[1]

		switch name {
		case "fileMode":
			i, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return dev, err
			}
			mode := os.FileMode(i)
			dev.FileMode = &mode
		case "uid":
			i, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return dev, err
			}
			uid := uint32(i)
			dev.UID = &uid

		case "gid":
			i, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return dev, err
			}
			gid := uint32(i)
			dev.GID = &gid
		default:
			return dev, fmt.Errorf("'%s' is not supported by device section", name)
		}
	}

	return dev, nil

var cgroupDeviceType = map[string]bool{
	"a": true, // all
	"b": true, // block device
	"c": true, // character device
}
var cgroupDeviceAccess = map[string]bool{
	"r": true, //read
	"w": true, //write
	"m": true, //mknod
}

// parseLinuxResourcesDeviceAccess parses the raw string passed with the --device-access-add flag
func parseLinuxResourcesDeviceAccess(device string, g *generate.Generator) (rspec.DeviceCgroup, error) {
	var allow bool
	var devType, access *string
	var major, minor *int64

	argsParts := strings.Split(device, ",")

	switch argsParts[0] {
	case "allow":
		allow = true
	case "deny":
		allow = false
	default:
		return rspec.DeviceCgroup{},
			fmt.Errorf("Only 'allow' and 'deny' are allowed in the first field of device-access-add: %s", device)
	}

	for _, s := range argsParts[1:] {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return rspec.DeviceCgroup{}, fmt.Errorf("Incomplete device-access-add arguments: %s", s)
		}
		name, value := parts[0], parts[1]

		switch name {
		case "type":
			if !cgroupDeviceType[value] {
				return rspec.DeviceCgroup{}, fmt.Errorf("Invalid device type in device-access-add: %s", value)
			}
			devType = &value
		case "major":
			i, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return rspec.DeviceCgroup{}, err
			}
			major = &i
		case "minor":
			i, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return rspec.DeviceCgroup{}, err
			}
			minor = &i
		case "access":
			for _, c := range strings.Split(value, "") {
				if !cgroupDeviceAccess[c] {
					return rspec.DeviceCgroup{}, fmt.Errorf("Invalid device access in device-access-add: %s", c)
				}
			}
			access = &value
		}
	}
	return rspec.DeviceCgroup{
		Allow:  allow,
		Type:   devType,
		Major:  major,
		Minor:  minor,
		Access: access,
	}, nil
}

func addSeccomp(context *cli.Context, g *generate.Generator) error {

	// Set the DefaultAction of seccomp
	if context.IsSet("linux-seccomp-default") {
		seccompDefault := context.String("linux-seccomp-default")
		err := g.SetDefaultSeccompAction(seccompDefault)
		if err != nil {
			return err
		}
	} else if context.IsSet("linux-seccomp-default-force") {
		seccompDefaultForced := context.String("linux-seccomp-default-force")
		err := g.SetDefaultSeccompActionForce(seccompDefaultForced)
		if err != nil {
			return err
		}
	}

	// Add the additional architectures permitted to be used for system calls
	if context.IsSet("linux-seccomp-arch") {
		seccompArch := context.String("linux-seccomp-arch")
		architectureArgs := strings.Split(seccompArch, ",")
		for _, arg := range architectureArgs {
			err := g.SetSeccompArchitecture(arg)
			if err != nil {
				return err
			}
		}
	}

	if context.IsSet("linux-seccomp-errno") {
		err := seccompSet(context, "errno", g)
		if err != nil {
			return err
		}
	}

	if context.IsSet("linux-seccomp-kill") {
		err := seccompSet(context, "kill", g)
		if err != nil {
			return err
		}
	}

	if context.IsSet("linux-seccomp-trace") {
		err := seccompSet(context, "trace", g)
		if err != nil {
			return err
		}
	}

	if context.IsSet("linux-seccomp-trap") {
		err := seccompSet(context, "trap", g)
		if err != nil {
			return err
		}
	}

	if context.IsSet("linux-seccomp-allow") {
		err := seccompSet(context, "allow", g)
		if err != nil {
			return err
		}
	}

	if context.IsSet("linux-seccomp-remove") {
		seccompRemove := context.String("linux-seccomp-remove")
		err := g.RemoveSeccompRule(seccompRemove)
		if err != nil {
			return err
		}
	}

	if context.Bool("linux-seccomp-remove-all") {
		err := g.RemoveAllSeccompRules()
		if err != nil {
			return err
		}
	}
	return nil
}

func seccompSet(context *cli.Context, seccompFlag string, g *generate.Generator) error {
	flagInput := context.String("seccomp-" + seccompFlag)
	flagArgs := strings.Split(flagInput, ",")
	setSyscallArgsSlice := []seccomp.SyscallOpts{}
	for _, flagArg := range flagArgs {
		comparisonArgs := strings.Split(flagArg, ":")
		if len(comparisonArgs) == 5 {
			setSyscallArgs := seccomp.SyscallOpts{
				Action:   seccompFlag,
				Syscall:  comparisonArgs[0],
				Index:    comparisonArgs[1],
				Value:    comparisonArgs[2],
				ValueTwo: comparisonArgs[3],
				Operator: comparisonArgs[4],
			}
			setSyscallArgsSlice = append(setSyscallArgsSlice, setSyscallArgs)
		} else if len(comparisonArgs) == 1 {
			setSyscallArgs := seccomp.SyscallOpts{
				Action:  seccompFlag,
				Syscall: comparisonArgs[0],
			}
			setSyscallArgsSlice = append(setSyscallArgsSlice, setSyscallArgs)
		} else {
			return fmt.Errorf("invalid syscall argument formatting %v", comparisonArgs)
		}

		for _, r := range setSyscallArgsSlice {
			err := g.SetSyscallAction(r)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// readKVStrings reads a file of line terminated key=value pairs, and overrides any keys
// present in the file with additional pairs specified in the override parameter
//
// This function is copied from github.com/docker/docker/runconfig/opts/parse.go
func readKVStrings(files []string, override []string) ([]string, error) {
	envVariables := []string{}
	for _, ef := range files {
		parsedVars, err := parseEnvFile(ef)
		if err != nil {
			return nil, err
		}
		envVariables = append(envVariables, parsedVars...)
	}
	// parse the '-e' and '--env' after, to allow override
	envVariables = append(envVariables, override...)

	return envVariables, nil
}

// parseEnv splits a given environment variable (of the form name=value) into
// (name, value). An error is returned if there is no "=" in the line or if the
// name is empty.
func parseEnv(env string) (string, string, error) {
	parts := strings.SplitN(env, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("environment variable must contain '=': %s", env)
	}

	name, value := parts[0], parts[1]
	if name == "" {
		return "", "", fmt.Errorf("environment variable must have non-empty name: %s", env)
	}
	return name, value, nil
}

// parseEnvFile reads a file with environment variables enumerated by lines
//
// ``Environment variable names used by the utilities in the Shell and
// Utilities volume of IEEE Std 1003.1-2001 consist solely of uppercase
// letters, digits, and the '_' (underscore) from the characters defined in
// Portable Character Set and do not begin with a digit. *But*, other
// characters may be permitted by an implementation; applications shall
// tolerate the presence of such names.''
// -- http://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap08.html
//
// As of #16585, it's up to application inside docker to validate or not
// environment variables, that's why we just strip leading whitespace and
// nothing more.
//
// This function is copied from github.com/docker/docker/runconfig/opts/envfile.go
func parseEnvFile(filename string) ([]string, error) {
	fh, err := os.Open(filename)
	if err != nil {
		return []string{}, err
	}
	defer fh.Close()

	lines := []string{}
	scanner := bufio.NewScanner(fh)
	currentLine := 0
	utf8bom := []byte{0xEF, 0xBB, 0xBF}
	for scanner.Scan() {
		scannedBytes := scanner.Bytes()
		if !utf8.Valid(scannedBytes) {
			return []string{}, fmt.Errorf("env file %s contains invalid utf8 bytes at line %d: %v", filename, currentLine+1, scannedBytes)
		}
		// We trim UTF8 BOM
		if currentLine == 0 {
			scannedBytes = bytes.TrimPrefix(scannedBytes, utf8bom)
		}
		// trim the line from all leading whitespace first
		line := strings.TrimLeftFunc(string(scannedBytes), unicode.IsSpace)
		currentLine++
		// line is not empty, and not starting with '#'
		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			data := strings.SplitN(line, "=", 2)

			// trim the front of a variable, but nothing else
			variable := strings.TrimLeft(data[0], whiteSpaces)
			if strings.ContainsAny(variable, whiteSpaces) {
				return []string{}, ErrBadEnvVariable{fmt.Sprintf("variable '%s' has white spaces", variable)}
			}

			if len(data) > 1 {

				// pass the value through, no trimming
				lines = append(lines, fmt.Sprintf("%s=%s", variable, data[1]))
			} else {
				// if only a pass-through variable is given, clean it up.
				lines = append(lines, fmt.Sprintf("%s=%s", strings.TrimSpace(line), os.Getenv(line)))
			}
		}
	}
	return lines, scanner.Err()
}

var whiteSpaces = " \t"

// ErrBadEnvVariable typed error for bad environment variable
type ErrBadEnvVariable struct {
	msg string
}

func (e ErrBadEnvVariable) Error() string {
	return fmt.Sprintf("poorly formatted environment: %s", e.msg)
}
