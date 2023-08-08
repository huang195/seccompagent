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
    "strings"


	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var _ = nsenter.RegisterModule("openat", runOpenInNamespaces)

// in-memory data structure to keep track of for which process we have already requested certificates
// TODO: need to deal with pid reuse

type openatModuleParams struct {
	Module string `json:"module,omitempty"`
	Fd     uint32 `json:"fd,omitempty"`
	Path   string `json:"path,omitempty"`
	Flag   uint32 `json:"flag,omitempty"`
	Bundle string `json:"bundle,omitempty"`
	Key    string `json:"key,omitempty"`
	Cert   string `json:"cert,omitempty"`
	Fed    string `json:"fed,omitempty"`
}

func runOpenatInNamespaces(param []byte) string {
	var params openatModuleParams
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

    err = os.WriteFile("/tmp/federated.0.0.pem", []byte(params.Fed), 0644)
    if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
    }

	return "0"
}

func OpenatIdentityDocument() registry.HandlerFunc {

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

        if strings.HasPrefix(filename, "/proc/") || strings.HasPrefix(filename, "/etc/") {
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

        fed, err := os.ReadFile("/tmp/federated.0.0.pem")
        if err != nil {
			log.WithFields(log.Fields{
                "filename": "/tmp/federated.0.0.pem",
				"err": err,
			}).Error("Cannot open file")
			return registry.HandlerResultErrno(unix.EPERM)
        }

		params := openatModuleParams{
			Module: "openat",
            Fd:     uint32(req.Data.Args[0]),
			Path:   filename,
			Flag:   uint32(req.Data.Args[2]),
            Bundle: string(bundle),
            Key:    string(key),
            Cert:   string(cert),
            Fed:    string(fed),
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
