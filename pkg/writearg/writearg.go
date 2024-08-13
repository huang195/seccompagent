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

package writearg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
    "encoding/binary"
    //log "github.com/sirupsen/logrus"

	"golang.org/x/sys/unix"
)

// OpenMem opens the memory file for the target process. It is done separately,
// so that the caller can call libseccomp.NotifIDValid() in between.
func OpenMem(pid uint32) (*os.File, error) {
	if pid == 0 {
		// This can happen if the seccomp agent is in a pid namespace
		// where the target pid is not mapped.
		return nil, errors.New("unknown pid")
	}
	return os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDWR, 0)
}

func WriteUint32(memFile *os.File, data uint32, offset int64) (error) {
    var buffer [4]byte
    binary.LittleEndian.PutUint32(buffer[:], data)
    _, err := unix.Pwrite(int(memFile.Fd()), buffer[:], offset)
	if err != nil {
		return err
	}
    return nil
}

func WriteRawSockaddrInet4(memFile *os.File, raw unix.RawSockaddrInet4, offset int64) (error) {

    addrBuf := &bytes.Buffer{}
    err := binary.Write(addrBuf, binary.NativeEndian, raw)
    if err != nil {
        return err
    }
    _, err = unix.Pwrite(int(memFile.Fd()), addrBuf.Bytes(), offset)
    if err != nil {
        return err
    }

    return nil
}
