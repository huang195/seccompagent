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
    //"bufio"
    "strings"
    //"regexp"
    //"unicode"
    "io"
    "path/filepath"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

    //"k8s.io/apimachinery/pkg/types"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

    "github.com/spiffe/spire/pkg/agent/common/cgroups"
)

const (
    // Cgroup path for a container in a pod in a non-Systemd environment
    CgroupPathTemplate  = "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod%s.slice/cri-containerd-%s.scope/cgroup.procs"

    // Cgroup path for a container in a pod in a Systemd environment
    CgroupPathTemplateSystemd = "/sys/fs/cgroup/systemd/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice/crio-%s.scope/cgroup.procs"
)

var _ = nsenter.RegisterModule("open", runInNamespaces)

// in-memory data structure to keep track of for which process we have already requested certificates
// TODO: need to deal with pid reuse
var pidMap = make(map[string]int)

type moduleParams struct {
    Module string `json:"module,omitempty"`
	Bundle string `json:"bundle,omitempty"`
	Key    string `json:"key,omitempty"`
	Cert   string `json:"cert,omitempty"`
    Fed    string `json:"fed,omitempty"`
}

func runInNamespaces(param []byte) string {
	var params moduleParams
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

    err = os.WriteFile("/tmp/federated_bundle.0.0.pem", []byte(params.Fed), 0400)
    if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
    }
	return "0"
}

//TODO: need to deal with partial failures - how to take us back to the original cgroups
func EnterCgroup(sourcePID int32, targetPID int32) error {
    cgroups, err := cgroups.GetCgroups(targetPID, dirFS("/"))
    if err != nil {
        log.WithFields(log.Fields{
            "sourcePID": sourcePID,
            "targetPID": targetPID,
            "err": err,
        }).Error("Cannot find cgroup")
        return err
    }

    for _, cgroup := range cgroups {
        controllerList := cgroup.ControllerList
        groupPath := cgroup.GroupPath

        // deal with entries like "1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod716f46c3_4f60_4d5b_ba75_d490d2f6606e.slice/crio-e316ba35da8609397348f35ef95e6671775d595c43a661a8153b119dd2d51d63.scope"
        substrings := strings.SplitN(controllerList, "=", 2)
        if len(substrings) == 2 {
            controllerList= substrings[1]
        }

        log.WithFields(log.Fields{
            "controllerList": controllerList,
            "groupPath": groupPath,
            "sourcePID": sourcePID,
            "targetPID": targetPID,
        }).Trace("EnterCgroup()")

        // e.g., path=/sys/fs/cgroup/systemd/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod716f46c3_4f60_4d5b_ba75_d490d2f6606e.slice/crio-e316ba35da8609397348f35ef95e6671775d595c43a661a8153b119dd2d51d63.scope/cgroup.procs
        path := fmt.Sprintf("/sys/fs/cgroup/%s%s/cgroup.procs", controllerList, groupPath)

        data, err := os.ReadFile(path)
        if err != nil {
            log.WithFields(log.Fields{
                "path": path,
                "err": err,
            }).Error("Cannot read cgroup file")
            return err
        }

        log.WithFields(log.Fields{
            "cgroup.procs": string(data),
        }).Trace("Read cgroup file (before)")

        err = os.WriteFile(path, []byte(strconv.Itoa(int(sourcePID))), 0644)
        if err != nil {
            log.WithFields(log.Fields{
                "path": path,
                "err": err,
            }).Error("Cannot join cgroup")
            return err
        }

        data, err = os.ReadFile(path)
        if err != nil {
            log.WithFields(log.Fields{
                "path": path,
                "err": err,
            }).Error("Cannot read cgroup file")
            return err
        }

        log.WithFields(log.Fields{
            "cgroup.procs": string(data),
        }).Trace("Read cgroup file (after)")
    }
    return nil
}

func OpenIdentityDocument() registry.HandlerFunc {

    // Getting our own pid to find our cgroup
    myPID := os.Getpid()
    log.WithFields(log.Fields{
        "myPID": myPID,
    }).Trace("OpenIdentityDocument()")

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

		filename, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot read argument")
			return registry.HandlerResultErrno(unix.EFAULT)
		}
        log.WithFields(log.Fields{
            "req.Pid": req.Pid,
            "filename":  filename,
        }).Trace("open()")

        // TODO: we currently only monitor for X509 key/cert files in PEM format and in
        // these file extensions. JWT and X509 DER support can be added later
        if !strings.HasSuffix(filename, ".crt") && !strings.HasSuffix(filename, ".pem") &&
           !strings.HasSuffix(filename, ".cer") && !strings.HasSuffix(filename, ".key") {
            return registry.HandlerResultContinue()
        }

        if strings.HasPrefix(filename, "/proc/") || strings.HasPrefix(filename, "/etc/") {
            return registry.HandlerResultContinue()
        }

        // Before we can move ourselves to the workload's cgroup, we need to create a dummy thread to hold on to our current cgroup so it doesn't get cleaned up
        sleepCmd := exec.Command("sleep", "infinity")
        err = sleepCmd.Start()
        if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Cannot create a dummy process")
            return registry.HandlerResultContinue()
        }

        sleepPID := sleepCmd.Process.Pid

        // Enter workload's cgroup
        err = EnterCgroup(int32(myPID), int32(req.Pid))
        if err != nil {
            return registry.HandlerResultContinue()
        }

        // Call spire-agent to retrieve certificate while within the workload's cgroup
        cmd := exec.Command("/bin/spire-agent", "api", "fetch", "-socketPath", "/run/spire/agent-sockets/spire-agent.sock", "-write", "/tmp")
        //cmd := exec.Command("/bin/spire-agent", "api", "fetch", "-socketPath", "/run/spire/sockets/agent.sock", "-write", "/tmp")
        stdoutStderr, err := cmd.CombinedOutput()
        if err != nil {
			log.WithFields(log.Fields{
				"err": err,
                "output": string(stdoutStderr),
			}).Error("Call to spire-agent failed")
            EnterCgroup(int32(myPID), int32(sleepPID))
            return registry.HandlerResultContinue()
        }

        // Put us back to the original cgroup
        err = EnterCgroup(int32(myPID), int32(sleepPID))
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

        fed, err := os.ReadFile("/tmp/federated_bundle.0.0.pem")
        if err != nil {
            // allow non-federated mode
            fed = []byte("")
        }

		params := moduleParams{
            Module: "open",
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

		//return registry.HandlerResultSuccess()
        return registry.HandlerResultContinue()
	}
}

type dirFS string

func (d dirFS) Open(p string) (io.ReadCloser, error) {
    return os.Open(filepath.Join(string(d), p))
}
