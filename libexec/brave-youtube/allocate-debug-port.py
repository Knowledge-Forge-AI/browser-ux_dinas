#!/usr/bin/env python3
import socket


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        print(server.getsockname()[1])


if __name__ == "__main__":
    main()
