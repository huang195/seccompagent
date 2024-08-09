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
    //"encoding/json"
	"fmt"
	//"strconv"
    //"os"
    //"unsafe"

	//"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/writearg"
    //"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

    // #cgo LDFLAGS: -lseccomp
    // 
    // #include <linux/seccomp.h>
    // #include <sys/ioctl.h>
    //
    // int seccomp_ioctl_notif_addfd(int notifyfd, __u64 id,  __u32 fd) {
    //   struct seccomp_notif_addfd addfd;
    //   addfd.id = id;
    //   addfd.srcfd = fd;
    //   addfd.newfd = 0;
    //   addfd.flags = 0;
    //   addfd.newfd_flags = 0;
    //   return ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    // }
    "C"
)

func AcceptLZT() registry.HandlerFunc {
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {

		memFile, err := writearg.OpenMem(req.Pid)
		if err != nil {
			return registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResultIntr()
		}

        socket := int(req.Data.Args[0])

        log.WithFields(log.Fields{
            "socket": socket,
        }).Trace("AcceptLZT: accept() caught")

        pidfd, err := unix.PidfdOpen(int(req.Pid), 0)
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("acceptLZT: PidfdOpen() failed")
            return registry.HandlerResultContinue()
        }
        defer unix.Close(pidfd)

        log.WithFields(log.Fields{
            "pid": req.Pid,
            "pidfd": pidfd,
        }).Trace("acceptLZT: calling PidfdOpen()")

        newfd, err := unix.PidfdGetfd(pidfd, socket, 0)
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("acceptLZT: PidfdGetfd() failed")
            return registry.HandlerResultContinue()
        }
        defer unix.Close(newfd)

        log.WithFields(log.Fields{
            "pid": req.Pid,
            "fd": newfd,
        }).Trace("acceptLZT: calling PidGetfd()")

        nfd, sa, err := unix.Accept(newfd)
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("acceptLZT Accept failed")
            return registry.HandlerResultErrno(err)
        }
        defer unix.Close(nfd)

        sockaddr_len := 0
        sockaddr_family := 0
        switch sa.(type) {
        case *unix.SockaddrInet4:
            sockaddr_len = 16
            sockaddr_family = 2
            log.Trace("acceptLZT: SockaddrInet4 socket detected")
        case *unix.SockaddrInet6:
            sockaddr_len = 28
            sockaddr_family = 10
            log.Trace("acceptLZT: SockaddrInet6 socket detected")
        default:
            log.Trace("acceptLZT: Unknown socket type detected")
        }

        log.WithFields(log.Fields{
            "pid": req.Pid,
            "nfd": nfd,
            "sa": sa,
        }).Trace("acceptLZT: Accept() returns")

        if sockaddr_len == 0 || sockaddr_family == 0 {
            return registry.HandlerResultErrno(fmt.Errorf("cannot handle socket type"))
        }

        targetfd := int(C.seccomp_ioctl_notif_addfd(C.int(fd), C.ulonglong(req.ID), C.uint(nfd)))
        if targetfd < 0 {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": targetfd,
            }).Error("acceptLZT: Accept() failed")
            return registry.HandlerResultErrno(fmt.Errorf("ioctl returned %v", targetfd))
        }

        log.WithFields(log.Fields{
                "targetfd": targetfd,
        }).Trace("acceptLZT: seccomp_ioctl_notif_addfd() returns")

		//err = writearg.WriteUint32(memFile, uint32(sockaddr_len), int64(req.Data.Args[2]))

        return registry.HandlerResult{Val: uint64(targetfd)}
	}
}
