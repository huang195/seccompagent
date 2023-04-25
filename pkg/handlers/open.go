// Copyright 2020-2021 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"
    "os"
    "os/exec"
    //"time"
    "bufio"
    "strings"
    "regexp"
    "unicode"
    "io/ioutil"


	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

    "k8s.io/apimachinery/pkg/types"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var _ = nsenter.RegisterModule("openat", runOpenInNamespaces)

// in-memory data structure to keep track of for which process we have already requested certificates
// TODO: need to deal with pid reuse
var pidMap = make(map[string]int)

type openModuleParams struct {
	Module string `json:"module,omitempty"`
	Fd     uint32 `json:"fd,omitempty"`
	Path   string `json:"path,omitempty"`
	Flag   uint32 `json:"flag,omitempty"`
	Bundle string `json:"bundle,omitempty"`
	Key    string `json:"key,omitempty"`
	Cert   string `json:"cert,omitempty"`
}

func runOpenInNamespaces(param []byte) string {
	var params openModuleParams
	err := json.Unmarshal(param, &params)
	if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
	}

    err = os.WriteFile("/tmp/bundle.0.pem", []byte(params.Bundle), 0644)
    if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
    }

    err = os.WriteFile("/tmp/svid.0.pem", []byte(params.Cert), 0644)
    if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
    }

    err = os.WriteFile("/tmp/svid.0.key", []byte(params.Key), 0400)
    if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
    }

	return "0"
}

// Cgroup represents a linux cgroup.
type Cgroup struct {
    HierarchyID    string
    ControllerList string
    GroupPath      string
}

// GetCGroups returns a slice of cgroups for pid using fs for filesystem calls.
//
// The expected cgroup format is "hierarchy-ID:controller-list:cgroup-path", and
// this function will return an error if every cgroup does not meet that format.
//
// For more information, see:
//   - http://man7.org/linux/man-pages/man7/cgroups.7.html
//   - https://www.kernel.org/doc/Documentation/cgroup-v2.txt
func GetCgroups(pid int32) ([]Cgroup, error) {
    path := fmt.Sprintf("/proc/%v/cgroup", pid)
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var cgroups []Cgroup
    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        token := scanner.Text()
        substrings := strings.SplitN(token, ":", 3)
        if len(substrings) < 3 {
            return nil, fmt.Errorf("cgroup entry contains %v colons, but expected at least 2 colons: %q", len(substrings), token)
        }
        cgroups = append(cgroups, Cgroup{
            HierarchyID:    substrings[0],
            ControllerList: substrings[1],
            GroupPath:      substrings[2],
        })
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return cgroups, nil
}

// regexes listed here have to exclusively match a cgroup path
// the regexes must include two named groups "poduid" and "containerid"
// if the regex needs to exclude certain substrings, the "mustnotmatch" group can be used
var cgroupREs = []*regexp.Regexp{
    // the regex used to parse out the pod UID and container ID from a
    // cgroup name. It assumes that any ".scope" suffix has been trimmed off
    // beforehand.  CAUTION: we used to verify that the pod and container id were
    // descendants of a kubepods directory, however, as of Kubernetes 1.21, cgroups
    // namespaces are in use and therefore we can no longer discern if that is the
    // case from within SPIRE agent container (since the container itself is
    // namespaced). As such, the regex has been relaxed to simply find the pod UID
    // followed by the container ID with allowances for arbitrary punctuation, and
    // container runtime prefixes, etc.
    regexp.MustCompile(`` +
        // "pod"-prefixed Pod UID (with punctuation separated groups) followed by punctuation
        `[[:punct:]]pod(?P<poduid>[[:xdigit:]]{8}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{12})[[:punct:]]` +
        // zero or more punctuation separated "segments" (e.g. "docker-")
        `(?:[[:^punct:]]+[[:punct:]])*` +
        // non-punctuation end of string, i.e., the container ID
        `(?P<containerid>[[:^punct:]]+)$`),

    // This regex applies for container runtimes, that won't put the PodUID into
    // the cgroup name.
    // Currently only cri-o in combination with kubeedge is known for this abnormally.
    regexp.MustCompile(`` +
        // intentionally empty poduid group
        `(?P<poduid>)` +
        // mustnotmatch group: cgroup path must not include a poduid
        `(?P<mustnotmatch>pod[[:xdigit:]]{8}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{12}[[:punct:]])?` +
        // /crio-
        `(?:[[:^punct:]]*/*)*crio[[:punct:]]` +
        // non-punctuation end of string, i.e., the container ID
        `(?P<containerid>[[:^punct:]]+)$`),
}

func reSubMatchMap(r *regexp.Regexp, str string) map[string]string {
    match := r.FindStringSubmatch(str)
    if match == nil {
        return nil
    }
    subMatchMap := make(map[string]string)
    for i, name := range r.SubexpNames() {
        if i != 0 {
            subMatchMap[name] = match[i]
        }
    }
    return subMatchMap
}

func isValidCGroupPathMatches(matches map[string]string) bool {
    if matches == nil {
        return false
    }
    if matches["mustnotmatch"] != "" {
        return false
    }
    return true
}

// canonicalizePodUID converts a Pod UID, as represented in a cgroup path, into
// a canonical form. Practically this means that we convert any punctuation to
// dashes, which is how the UID is represented within Kubernetes.
func canonicalizePodUID(uid string) types.UID {
    return types.UID(strings.Map(func(r rune) rune {
        if unicode.IsPunct(r) {
            r = '-'
        }
        return r
    }, uid))
}

func getPodUIDAndContainerIDFromCGroupPath(cgroupPath string) (string, string, bool) {
    // We are only interested in kube pods entries, for example:
    // - /kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
    // - /docker/8d461fa5765781bcf5f7eb192f101bc3103d4b932e26236f43feecfa20664f96/kubepods/besteffort/poddaa5c7ee-3484-4533-af39-3591564fd03e/aff34703e5e1f89443e9a1bffcc80f43f74d4808a2dd22c8f88c08547b323934
    // - /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c48913c-b29f-11e7-9350-020968147796.slice/docker-9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961.scope
    // - /kubepods-besteffort-pod72f7f152_440c_66ac_9084_e0fc1d8a910c.slice:cri-containerd:b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2"
    // - /../../pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
    // - 0::/../crio-45490e76e0878aaa4d9808f7d2eefba37f093c3efbba9838b6d8ab804d9bd814.scope
    // First trim off any .scope suffix. This allows for a cleaner regex since
    // we don't have to muck with greediness. TrimSuffix is no-copy so this
    // is cheap.
    cgroupPath = strings.TrimSuffix(cgroupPath, ".scope")

    var matchResults map[string]string
    for _, regex := range cgroupREs {
        matches := reSubMatchMap(regex, cgroupPath)
        if isValidCGroupPathMatches(matches) {
            if matchResults != nil {
                log.Printf("More than one regex matches for cgroup %s", cgroupPath)
                return "", "", false
            }
            matchResults = matches
        }
    }

    if matchResults != nil {
        var podUID string
        if matchResults["poduid"] != "" {
            //podUID = canonicalizePodUID(matchResults["poduid"])
            podUID = matchResults["poduid"]
        }
        return podUID, matchResults["containerid"], true
    }
    return "", "", false
}

func getPodUIDAndContainerIDFromCGroups(cgroups []Cgroup) (string, string, error) {
    var podUID string
    var containerID string
    for _, cgroup := range cgroups {
        candidatePodUID, candidateContainerID, ok := getPodUIDAndContainerIDFromCGroupPath(cgroup.GroupPath)
        switch {
        case !ok:
            // Cgroup did not contain a container ID.
            continue
        case containerID == "":
            // This is the first container ID found so far.
            podUID = candidatePodUID
            containerID = candidateContainerID
        case containerID != candidateContainerID:
            // More than one container ID found in the cgroups.
            return "", "", fmt.Errorf("multiple container IDs found in cgroups (%s, %s)",
                containerID, candidateContainerID)
        case podUID != candidatePodUID:
            // More than one pod UID found in the cgroups.
            return "", "", fmt.Errorf("multiple pod UIDs found in cgroups (%s, %s)",
                podUID, candidatePodUID)
        }
    }

    return podUID, containerID, nil
}

func GetPodUIDAndContainerID(pID int32) (string, string, error) {
    cgroups, err := GetCgroups(pID)
    if err != nil {
        return "", "", fmt.Errorf("unable to obtain cgroups: %v", err)
    }

    return getPodUIDAndContainerIDFromCGroups(cgroups)
}

func EnterCgroup(path string, pid int) error {
    err := ioutil.WriteFile(path, []byte(strconv.Itoa(pid)), 0644)
    if err != nil {
        log.WithFields(log.Fields{
            "cgroup.procs": path,
            "err": err,
        }).Error("Cannot join cgroup")
        return fmt.Errorf("Cannot join cgroup")
    }
    return nil
}

func OpenIdentityDocument() registry.HandlerFunc {

    // Getting our own pid to find our cgroup
    myPID := os.Getpid()
    myPodUID, myContainerID, err := GetPodUIDAndContainerID(int32(myPID))
    if err != nil {
        log.WithFields(log.Fields{
            "err": err,
        }).Error("Cannot retrieve pod and container ID")
        return nil
    }

    // TODO: we're hardcoding the cgroup path here, need a better way
    myCgroupProcPath := fmt.Sprintf("/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod%s.slice/cri-containerd-%s.scope/cgroup.procs", myPodUID, myContainerID)

    log.WithFields(log.Fields{
        "pod": myPodUID,
        "container": myContainerID,
        "cgroup.procs": myCgroupProcPath,
    }).Trace("Successfully retrieved our own pod and container ID")

	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
        // Step 1: Masquerade as the workload by jumping to its cgroup

		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResultIntr()
		}

		filename, err := readarg.ReadString(memFile, int64(req.Data.Args[1]))
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot read argument")
			return registry.HandlerResultErrno(unix.EFAULT)
		}
        log.WithFields(log.Fields{
            "filename":  filename,
        }).Trace("openat()")

        podUID, containerID, err := GetPodUIDAndContainerID(int32(req.Pid))
        if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot retrieve pod and container ID")
            return registry.HandlerResultContinue()
        }

        // do nothing if we have already handled certificate retrival for this pid
        if _, ok := pidMap[podUID]; ok {
            return registry.HandlerResultContinue()
        }

        // TODO: we currently only monitor for X509 key/cert files in PEM format and in
        // these file extensions. JWT and X509 DER support can be added later
        if !strings.HasSuffix(filename, ".crt") && !strings.HasSuffix(filename, ".pem") &&
           !strings.HasSuffix(filename, ".cer") && !strings.HasSuffix(filename, ".key") {
            return registry.HandlerResultContinue()
        }

        // TODO: we're hardcoding the cgroup path here, need a better way
        cgroupProcPath := fmt.Sprintf("/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod%s.slice/cri-containerd-%s.scope/cgroup.procs", podUID, containerID)

        log.WithFields(log.Fields{
            "pod": podUID,
            "container": containerID,
            "cgroup.procs": cgroupProcPath,
        }).Trace("Successfully retrieved pod and container ID")

        // Before we can move ourselves to the workload's cgroup, we need to create a dummy thread to hold on to our current cgroup so it doesn't get cleaned up
        sleepCmd := exec.Command("sleep", "infinity")
        err = sleepCmd.Start()
        if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Cannot create a dummy process")
            return registry.HandlerResultContinue()
        }

        // Enter workload's cgroup
        err = EnterCgroup(cgroupProcPath, myPID)
        if err != nil {
            return registry.HandlerResultContinue()
        }

        // Call spire-agent to retrieve certificate while within the workload's cgroup
        cmd := exec.Command("/bin/spire-agent", "api", "fetch", "-socketPath", "/run/spire/sockets/agent.sock", "-write", "/tmp")
        stdoutStderr, err := cmd.CombinedOutput()
        if err != nil {
			log.WithFields(log.Fields{
				"err": err,
                "output": stdoutStderr,
			}).Error("Call to spire-agent failed")
            EnterCgroup(myCgroupProcPath, myPID)
            return registry.HandlerResultContinue()
        }

        // Put us back to the original cgroup
        err = EnterCgroup(myCgroupProcPath, myPID)
        if err != nil {
            sleepCmd.Process.Kill()
            return registry.HandlerResultContinue()
        }

        // Kill the dummy child goroutine
        err = sleepCmd.Process.Kill()
        if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Cannot kill the dummy process")
            return registry.HandlerResultContinue()
        }

        // Step 2: Setup nsenter to write certificate files to the workload's file system

        bundle, err := os.ReadFile("/tmp/bundle.0.pem")
        if err != nil {
			log.WithFields(log.Fields{
                "filename": "/tmp/bundle.0.pem",
				"err": err,
			}).Error("Cannot open file")
			return registry.HandlerResultErrno(unix.EPERM)
        }

        key, err := os.ReadFile("/tmp/svid.0.key")
        if err != nil {
			log.WithFields(log.Fields{
                "filename": "/tmp/svid.0.key",
				"err": err,
			}).Error("Cannot open file")
			return registry.HandlerResultErrno(unix.EPERM)
        }

        cert, err := os.ReadFile("/tmp/svid.0.pem")
        if err != nil {
			log.WithFields(log.Fields{
                "filename": "/tmp/svid.0.pem",
				"err": err,
			}).Error("Cannot open file")
			return registry.HandlerResultErrno(unix.EPERM)
        }

		params := openModuleParams{
			Module: "openat",
            Fd:     uint32(req.Data.Args[0]),
			Path:   filename,
			Flag:   uint32(req.Data.Args[2]),
            Bundle: string(bundle),
            Key:    string(key),
            Cert:   string(cert),
		}

        mntns, err := nsenter.OpenNamespace(req.Pid, "mnt")
        if err != nil {
            log.WithFields(log.Fields{
                "fd":  fd,
                "pid": req.Pid,
                "err": err,
            }).Error("Cannot open namespace")
            return registry.HandlerResultErrno(unix.EPERM)
        }
        defer mntns.Close()

        root, err := nsenter.OpenRoot(req.Pid)
        if err != nil {
            log.WithFields(log.Fields{
                "fd":  fd,
                "pid": req.Pid,
                "err": err,
            }).Error("Cannot open root")
            return registry.HandlerResultErrno(unix.EPERM)
        }
        defer root.Close()

        cwd, err := nsenter.OpenCwd(req.Pid)
        if err != nil {
            log.WithFields(log.Fields{
                "fd":  fd,
                "pid": req.Pid,
                "err": err,
            }).Error("Cannot open cwd")
            return registry.HandlerResultErrno(unix.EPERM)
        }
        defer cwd.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"req": req,
				"err": err,
			}).Debug("Notification no longer valid")
			return registry.HandlerResultIntr()
		}

		output, err := nsenter.Run(root, cwd, mntns, nil, nil, params)
		if err != nil {
			log.WithFields(log.Fields{
				"fd":     fd,
				"pid":    req.Pid,
				"output": output,
				"err":    err,
			}).Error("Run in target namespaces failed")
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		errno, err := strconv.Atoi(string(output))
		if err != nil {
			log.WithFields(log.Fields{
				"fd":     fd,
				"pid":    req.Pid,
				"output": output,
				"err":    err,
			}).Error("Cannot parse return value")
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		if errno != 0 {
			log.WithFields(log.Fields{
				"errno":    errno,
			}).Error("Errno is non-zero")
			return registry.HandlerResultErrno(unix.Errno(errno))
		}

        //TODO: clean up Pid from pidMap when process is terminated
        pidMap[podUID] = 1

		//return registry.HandlerResultSuccess()
        return registry.HandlerResultContinue()
	}
}
