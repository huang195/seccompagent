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
    //"net"
    "syscall"

	//"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

    // #cgo LDFLAGS: -lssl -lcrypto
    //
    // #include <openssl/ssl.h>
    // #include <openssl/err.h>
    // #include <sys/socket.h>
    // #include <netinet/in.h>
    // #include <unistd.h>
    // #include <string.h>
    //
    // #define CLIENT_CRT "/certs/client.crt"
    // #define CLIENT_KEY "/certs/client.key"
    // #define CA_CRT "/certs/ca.crt"
    //
    // //TODO: need to clean up SSL state after connection is teared down
    // int do_client_ssl_handshake(int fd) {
    //   const SSL_METHOD *method;
    //   SSL_CTX *ctx;
    //   SSL *ssl;
    //   int ret;
    //   BIO *bio;
    //
    //   SSL_load_error_strings();
    //   OpenSSL_add_ssl_algorithms();
    //
    //   method = TLS_client_method();
    //   ctx = SSL_CTX_new(method);
    //   if (!ctx) {
    //     perror("Unable to create SSL context");
    //     return -1;
    //   }
    //
    //   if (SSL_CTX_use_certificate_file(ctx, CLIENT_CRT, SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     return -1;
    //   }
    //   if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     return -1;
    //   }
    //   if (SSL_CTX_load_verify_locations(ctx, CA_CRT, NULL) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     return -1;
    //   }
    //
    //   ssl = SSL_new(ctx);
    //   if (!ssl) {
    //      perror("SSL_new returned null");
    //      return -1;
    //   }
    //
    //   ret = SSL_set_fd(ssl, fd);
    //   if (ret == 0) {
    //     perror("SSL_set_fd failed");
    //     return -1;
    //   }
    //   
    //   bio = BIO_new_socket(fd, BIO_NOCLOSE);
    //   if (!bio) {
    //     ERR_print_errors_fp(stderr);
    //     return -1;
    //   }
    //
    //   SSL_set_bio(ssl, bio, bio);
    //
    //   ret = SSL_connect(ssl);
    //   if (ret <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     return -1;
    //   } else {
    //     printf("SSL_accept() succeeded");
    //   }
    //   return 0;
    // }
    "C"

)

func connectHandshake(fd int) error {

    log.WithFields(log.Fields{
        "fd": fd,
    }).Trace("connectHandshake: write to the socket")

    _, err := syscall.Write(fd, []byte("*** handshake from the client ***"))
    if err != nil {
        return err
    }

    log.WithFields(log.Fields{
        "fd": fd,
    }).Trace("connectHandshake: read from the socket")

    buf := make([]byte, 1024)
    n, err := syscall.Read(fd, buf)
    if err != nil {
        return err
    }

    log.WithFields(log.Fields{
        "fd": fd,
        "message": string(buf[:n]),
    }).Trace("connectHandshake: server message received")

    return nil
}

func ConnectLZT() registry.HandlerFunc {
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {

		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResultIntr()
		}

        socket := int(req.Data.Args[0])
        sockaddr, err := readarg.ReadSockaddrInet4(memFile, int64(req.Data.Args[1]))
        if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot read argument")
            return registry.HandlerResultContinue()
        }
        address_len := uint(req.Data.Args[2])

        log.WithFields(log.Fields{
            "socket": socket,
            "address_len": address_len,
            "port": sockaddr.Port,
            "address": sockaddr.Addr,
        }).Trace("connect() call caught")

        // check if we are using IPv4
        if (address_len != 16) {
            return registry.HandlerResultContinue()
        }

        pidfd, err := unix.PidfdOpen(int(req.Pid), 0)
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("ConnectLZT: PidfdOpen() failed")
            return registry.HandlerResultContinue()
        }
        defer unix.Close(pidfd)

        log.WithFields(log.Fields{
            "pid": req.Pid,
            "pidfd": pidfd,
        }).Trace("ConnectLZT: PidfdOpen() returned")

        newfd, err := unix.PidfdGetfd(pidfd, socket, 0)
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("ConnectLZT: PidfdGetfd() failed")
            return registry.HandlerResultContinue()
        }
        defer unix.Close(newfd)

        log.WithFields(log.Fields{
            "pid": req.Pid,
            "fd": newfd,
        }).Trace("ConnectLZT: PidfdGetfd() returned")

        /*
        err = unix.SetNonblock(newfd, false)
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("ConnectLZT: SetNonblocking() failed")
            return registry.HandlerResultErrno(err)
        }
        */

        err = unix.Connect(newfd, &unix.SockaddrInet4{Port: int(sockaddr.Port), Addr: sockaddr.Addr})
        if err != nil {
            log.WithFields(log.Fields{
                "pid": req.Pid,
                "err": err,
            }).Error("ConnectLZT: Connect() failed")
            return registry.HandlerResultErrno(err)
        }

        log.WithFields(log.Fields{
            "pid": req.Pid,
        }).Trace("ConnectLZT: Connect() returned")

        // TODO: only if server port is 8080, we do handshake
        if sockaddr.Port == 8080 {
            /*
            err = connectHandshake(newfd)
            if err != nil {
                log.WithFields(log.Fields{
                    "err": err,
                }).Error("ConnectLZT: connect handshake failed")
                return registry.HandlerResultErrno(fmt.Errorf("handshake failed"))
            }
            */

            ret := C.do_client_ssl_handshake(C.int(newfd))
            if ret < 0 {
                log.WithFields(log.Fields{
                    "ret": ret,
                }).Error("ConnectLZT: connect handshake failed")
                return registry.HandlerResultErrno(fmt.Errorf("handshake failed"))
            }
        }

		return registry.HandlerResultSuccess()
	}
}
