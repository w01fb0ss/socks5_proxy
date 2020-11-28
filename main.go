package main

import (
	"net"

	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	logger, _ = zap.NewProduction()
}

func main() {
	// defer log sync
	defer logger.Sync()
	server, err := net.Listen("tcp", ":8888")
	if err != nil {
		logger.Sugar().Errorf("Listen failed: %v\n", err)
		return
	}

	// server.Accept
	for {
		client, err := server.Accept()
		if err != nil {
			logger.Sugar().Errorf("Accept failed: %v", err)
			continue
		}

		// process
		go process(client)
	}
}

func process(client net.Conn) {
	remoteAddr := client.RemoteAddr().String()
	logger.Sugar().Infof("Connection from %s\n", remoteAddr)

	// socks5 三板斧: 认证、连接、转发
	// 认证
	if err := Auth(client); err != nil {
		logger.Sugar().Error("auth failed: ", err)
		client.Close()
		return
	}

	// 连接
	target, err := Conn(client)
	if err != nil {
		logger.Sugar().Error("auth failed: ", err)
		client.Close()
		return
	}

	// 转发
	Forward(client, target)
}
