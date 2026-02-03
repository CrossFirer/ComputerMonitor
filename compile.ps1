# 编译脚本
Write-Host "开始编译监控软件..."

# 检查g++是否可用
try {
    g++ --version | Out-Null
} catch {
    Write-Host "错误: 未找到g++编译器，请确保MinGW已安装并添加到环境变量中。" -ForegroundColor Red
    exit 1
}

# 编译命令
g++ -std=c++11 monitor.cpp -o monitor.exe -lgdiplus -lpsapi -lpdh -liphlpapi -lole32 -loleaut32 -lwbemuuid -lgdi32 -mwindows

# 检查编译结果
if ($LASTEXITCODE -eq 0) {
    Write-Host "编译成功！生成了 monitor.exe 文件。" -ForegroundColor Green
    Write-Host "运行 ./monitor.exe 启动监控软件。" -ForegroundColor Yellow
} else {
    Write-Host "编译失败，请查看上面的错误信息。" -ForegroundColor Red
}
