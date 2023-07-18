package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"bufio"
	"path/filepath"
	"strings"
	"sync"
	"strconv"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

var MTDType = "rename"
var logPath = "../logs/logfile%d.csv"
var evaluateMTD = true // If true, creates new csv file every time period (2s, 5s, 10s). Otherwise, dumps all records into one csv for training purposes
var initialTimestamp = time.Now().Unix()
var timeWindow = 5

var mountPoint = "/home/john/FTP/" // Change the path to the desired mountpoint
var underlay = "/home/john/001"    // Change the path to the desired mountpoint

var delayingModifcations = false // Toggle to make any modifying ops delayed until the process is known
var checkLists = true
var w *bufio.Writer
var monitor = "pid,entropy,op,ext,filename,timestamp\n"

type RenameNode struct {
	fs.LoopbackNode
	Name string
}

type Status int32

type CsvDump struct {
	Pid       uint32
	Entropy   float64
	Op        string
	Ext       string
	Name      string
	Timestamp int64
}

func (m CsvDump) String() string {
	return fmt.Sprintf("%d,%f,%s,%s,%s,%d", m.Pid, m.Entropy, m.Op, m.Ext, m.Name, m.Timestamp)
}

type RenameFile struct {
	fs.LoopbackFile
	mu         sync.Mutex
	name       string
	node       *fs.LoopbackNode
	parentNode *fs.Inode
}



// In case we are evaluating in real settings, we create a new csv file every 10s
// Every csv file will be classified with non-malicious/malicious
func changeLogFile() {
	file, _ := os.Create("../logs/monitor.csv")
	w = bufio.NewWriter(file)

	interval := time.Duration(timeWindow) * time.Second
	ticker := time.NewTicker(interval)
	numLog := 1
	for range ticker.C {
	        file, _ := os.Create("../logs/monitor.csv")
	        w = bufio.NewWriter(file)
		fmt.Println("Writing monitor of " + strconv.FormatUint(uint64(numLog), 10))
		fmt.Println(monitor)
		fmt.Fprintln(w, monitor)
		w.Flush()
		monitor = "pid,entropy,op,ext,filename,timestamp\n"
		numLog++
		fmt.Println("Now monitor slice #" + strconv.FormatUint(uint64(numLog), 10))
	}
}

func NewLoopbackFile(fd int, name string, node *fs.LoopbackNode) fs.FileHandle {
	_, parentNode := node.Parent()
	return &RenameFile{

		LoopbackFile: fs.LoopbackFile{
			Fd: fd,
		},
		name:       name,
		node:       node,
		parentNode: parentNode,
	}
}

var _ = (fs.NodeOpener)((*RenameNode)(nil))
var _ = (fs.NodeCreater)((*RenameNode)(nil))
var _ = (fs.NodeUnlinker)((*RenameNode)(nil))
var _ = (fs.NodeRenamer)((*RenameNode)(nil))
var _ = (fs.FileReader)((*RenameFile)(nil))
var _ = (fs.FileWriter)((*RenameFile)(nil))

func (n *RenameNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	p := filepath.Join(n.path(), name)
	flags = flags &^ syscall.O_APPEND
	fd, err := syscall.Open(p, int(flags)|os.O_CREATE, mode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	n.PreserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, nil, 0, fs.ToErrno(err)
	}

	node := n.LoopbackNode.RootData.NewNode_(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.IdFromStat(&st))
	lf := NewLoopbackFile(fd, name, &n.LoopbackNode)

	out.FromStat(&st)
	return ch, lf, 0, 0
}

func (f *RenameFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	caller, _ := fuse.FromContext(ctx)
	pid := caller.Pid
	ext := strings.Split(f.name, ".")[1]
	entropy := GetEntropy(data)
	dt := time.Now().Unix() - initialTimestamp

	CsvDump := CsvDump{
		Pid:       pid,
		Entropy:   entropy,
		Op:        "write",
		Ext:       ext,
		Name:      f.name,
		Timestamp: dt,
	}
	monitor = monitor + CsvDump.String() + "\n"
	//fmt.Fprintln(w, CsvDump)
	//w.Flush()

	if checkLists {
		if isBlocklisted(pid) {
			fmt.Println("Ignore write to " + f.name + " (blacklisted)")
			return uint32(len(data)), fs.ToErrno(nil)
		}
		
		if isAllowlisted(pid) {
			fmt.Println("Execute write to " + f.name + " (allowlisted)")
			n, err := syscall.Pwrite(f.Fd, data, off)
			isMalicious(pid)
			return uint32(n), fs.ToErrno(err)
		}
	}

	if delayingModifcations {
		time.Sleep(5 * time.Second)
	}

	if isMalicious(pid) {
		fmt.Println("Ignore write to " + f.name)
		return uint32(len(data)), fs.ToErrno(nil)
	} else {
		fmt.Println("Execute write to " + f.name)
		n, err := syscall.Pwrite(f.Fd, data, off)
		return uint32(n), fs.ToErrno(err)
	}
}

func (f *RenameFile) Read(ctx context.Context, buf []byte, off int64) (res fuse.ReadResult, errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	caller, _ := fuse.FromContext(ctx)
	pid := caller.Pid
	//fmt.Println(pid)
	ext := strings.Split(f.name, ".")[1]
	if isMalicious(pid) {
		//f.node.Rename(ctx, f.name, f.parentNode, "_"+f.name, 0)
	}

	dt := time.Now().Unix() - initialTimestamp

	CsvDump := CsvDump{
		Pid:       pid,
		Entropy:   -1.0,
		Op:        "read",
		Ext:       ext,
		Name:      f.name,
		Timestamp: dt,
	}
	monitor = monitor + CsvDump.String() + "\n"

	//fmt.Fprintln(w, CsvDump)
	//w.Flush()

	r := fuse.ReadResultFd(uintptr(f.Fd), off, len(buf))
	return r, fs.OK
}

func newRenameNode(rootData *fs.LoopbackRoot, _ *fs.Inode, name string, _ *syscall.Stat_t) fs.InodeEmbedder {
	n := &RenameNode{
		LoopbackNode: fs.LoopbackNode{
			RootData: rootData,
		},
		Name: name,
	}
	return n
}

func (n *RenameNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	flags = flags &^ syscall.O_APPEND
	rootPath := n.Path(n.Root())
	path := filepath.Join(n.RootData.Path, rootPath)
	f, err := syscall.Open(path, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	lf := NewLoopbackFile(f, n.Name, &n.LoopbackNode)

	return lf, 0, 0
}

func (n *RenameNode) Unlink(ctx context.Context, name string) (errno syscall.Errno) {
	els := strings.Split(name, "/")
	fileToDel := els[len(els)-1]
	fmt.Println(underlay + "/" + fileToDel)


	caller, _ := fuse.FromContext(ctx)
	pid := caller.Pid

	if checkLists {

		if isBlocklisted(pid) {
			fmt.Println("Ignore unlink of " + name + " (blocklisted)")
			return fs.ToErrno(nil)
		}
		
		if isAllowlisted(pid) {
			fmt.Println("Unlink " + name + " (allowlisted)")
			err := syscall.Unlink(underlay + "/" + name)
			return fs.ToErrno(err)
		}
	}

	if delayingModifcations {
		time.Sleep(5 * time.Second)
	}

	if isMalicious(pid) {
		fmt.Println("Ignore unlink of " + name)
		return fs.ToErrno(nil)
	} else {
		fmt.Println("Execute unlink " + name)
		err := syscall.Unlink(underlay + "/" + name)
		return fs.ToErrno(err)
	}
}

func (n *RenameNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) (errno syscall.Errno) {
	fmt.Println("Rename " + name + " to " + newName)

	caller, _ := fuse.FromContext(ctx)
	pid := caller.Pid

	if checkLists {
		if isBlocklisted(pid) {
			fmt.Println("Ignore rename of " + name + " to " + newName + " (blocklisted)")
			return fs.ToErrno(nil)
		}
		
		if isAllowlisted(pid) {
			fmt.Println("Rename " + name + " to " + newName + " (allowlisted)")
			err := syscall.Rename(underlay+"/"+name, underlay+"/"+newName)
			return fs.ToErrno(err)
		}
	}

	if delayingModifcations {
		time.Sleep(5 * time.Second)
	}

	if isMalicious(pid) {
		fmt.Println("Ignore rename of " + name)
		return fs.ToErrno(nil)
	} else {
		fmt.Println("Execute rename of" + name)
	        // TODO: Implement proper renaming and non-trivial cases (e.g., subdirs)
	        err := syscall.Rename(underlay+"/"+name, underlay+"/"+newName)
		return fs.ToErrno(err)
	}
}

func (n *RenameNode) path() string {
	path := n.Path(n.Root())
	return filepath.Join(n.RootData.Path, path)
}

func main() {
	go changeLogFile()
	rootData := &fs.LoopbackRoot{
		NewNode: newRenameNode,
		Path:    underlay,
	}

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
	}

	opts.MountOptions.Options = append(opts.MountOptions.Options, "allow_other", "fsname=renameFS")
	opts.MountOptions.Name = "renameFS"
	opts.NullPermissions = true

	server, err := fs.Mount(mountPoint, newRenameNode(rootData, nil, "root", nil), opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	fmt.Println("Mounted!")
	server.Wait()
}