BINARY_NAME=rename_fs
MOUNTPOINT=/home/john/FTP

build:
	GOARCH=amd64 GOOS=linux go build -o ${BINARY_NAME}-linux -buildvcs=false

run: build
	mkdir -p /home/john/FTP
	./${BINARY_NAME}-linux

clean:
	go clean
	rm ${BINARY_NAME}-linux
	umount ${MOUNTPOINT}
