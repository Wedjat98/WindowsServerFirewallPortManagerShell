import http.server
import socketserver
import ssl
import argparse
import socket

def create_test_server(port, use_ssl=False):
    """创建一个简单的 HTTP 或 HTTPS 测试服务器。"""
    class MyHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            
            # 获取服务器信息
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>端口测试成功</title>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }}
                    .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .success {{ color: #28a745; font-size: 24px; font-weight: bold; }}
                    .info {{ color: #17a2b8; margin: 10px 0; }}
                    .highlight {{ background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success">🎉 端口 {port} 开放成功!</div>
                    <div class="info">服务器信息:</div>
                    <div class="highlight">
                        <strong>主机名:</strong> {hostname}<br>
                        <strong>内网IP:</strong> {local_ip}<br>
                        <strong>监听端口:</strong> {port}<br>
                        <strong>协议:</strong> {"HTTPS" if use_ssl else "HTTP"}<br>
                        <strong>客户端IP:</strong> {self.client_address[0]}
                    </div>
                    <div class="info">✅ 防火墙配置正确</div>
                    <div class="info">✅ 服务正常运行</div>
                </div>
            </body>
            </html>
            """
            self.wfile.write(bytes(message, "utf8"))

    # 明确绑定到所有网络接口
    bind_address = "0.0.0.0"  # 关键改动：明确绑定到所有接口
    
    if use_ssl:
        httpd = socketserver.TCPServer((bind_address, port), MyHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                     keyfile="key.pem",
                                     certfile="cert.pem",
                                     server_side=True)
        protocol = "HTTPS"
    else:
        httpd = socketserver.TCPServer((bind_address, port), MyHandler)
        protocol = "HTTP"
    
    # 获取本机IP信息
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print(f"🚀 {protocol} 服务器启动成功!")
    print(f"📍 监听地址: {bind_address}:{port}")
    print(f"🏠 主机名: {hostname}")
    print(f"🌐 内网IP: {local_ip}")
    print(f"")
    print(f"📱 访问地址:")
    print(f"   本机访问: http://localhost:{port}")
    print(f"   局域网访问: http://{local_ip}:{port}")
    print(f"")
    print(f"⏹️  按 Ctrl+C 停止服务器")
    print("-" * 50)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="创建一个用于防火墙测试的HTTP或HTTPS服务器。")
    parser.add_argument("port", type=int, help="服务器监听的端口")
    parser.add_argument("--ssl", action="store_true", help="使用SSL (HTTPS)")
    
    args = parser.parse_args()
    
    print(f"🔧 准备启动测试服务器...")
    print(f"📋 端口: {args.port}")
    print(f"🔒 SSL: {'启用' if args.ssl else '禁用'}")
    print("")
    
    create_test_server(args.port, args.ssl)
