// socks5 具体实现
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

/*
客户端请求服务端
|-------------|------------|------------|
| VER         | NMETHODS   | METHODS    |
|-------------|------------|------------|
|  1          |   1        |  1-255     |
|-------------|------------|------------|

* VER是SOCKS版本，这里应该是0x05；
* NMETHODS是METHODS部分的长度
* METHODS是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
	- 0x00 不需要认证
	- 0x01 GSSAPI
	- 0x02 用户名、密码认证
	- 0x03 - 0x7F由IANA分配（保留）
	- 0x80 - 0xFE为私人方法保留
	- 0xFF 无可接受的方法

服务端返回客户端
|-------------|------------|
| VER         | METHOD     |
|-------------|------------|
|  1          |   1        |
|-------------|------------|

*/
func Auth(client net.Conn) error {
	buf := make([]byte, 256)
	// 读取VER和NMETHODS
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}
	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// 读取 METHODS 列表
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	// 返回 5 0 不认证
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp err: " + err.Error())
	}

	return nil
}

/*
请求方
VER
0x05
CMD
连接方式，0x01=CONNECT, 0x02=BIND, 0x03=UDP ASSOCIATE
RSV
保留字段，现在没卵用
ATYP
地址类型，0x01=IPv4，0x03=域名，0x04=IPv6
DST.ADDR
目标地址，细节后面讲
DST.PORT
目标端口，2字节，网络字节序（network octec order）


返回方

VER
0x05
REP
状态码，0x00=成功，0x01=未知错误，……
RSV
依然是没卵用的 RESERVED
ATYP
地址类型
BND.ADDR
服务器和DST创建连接用的地址
BND.PORT
服务器和DST创建连接用的端口
*/

func Conn(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 {
		return nil, errors.New("invalid version")
	}
	if cmd != 1 {
		return nil, errors.New("invalid request type")
	}

	addr := ""
	switch atyp {
	case 1: // ipv4
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3: // 域名
		// 第一个字节为域名长度
		n, err := io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])
		// 剩余的内容为域名
		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])
	case 4:
		return nil, errors.New("IPv6: no supported yet")
	default:
		return nil, errors.New("invalid atyp")
	}

	// DST.PORT
	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	// 因cmd目前只为1，
	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}

	return dest, nil
}

func Forward(client net.Conn, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}
