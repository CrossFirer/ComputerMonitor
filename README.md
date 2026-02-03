# 横幅监控软件

AI写的一款基于C++和Windows API开发的系统监控软件，以半透明横幅形式显示在屏幕顶部，实时监控系统各项指标。

# 效果图：

<img width="1052" height="48" alt="image" src="https://github.com/user-attachments/assets/d44df0a8-f5fc-4c6b-8812-1e7cefa9363d" />


## 功能特性

- **实时系统监控**：显示FPS、CPU使用率、CPU温度、CPU频率、GPU使用率、GPU温度、GPU内存、内存使用率、网络速度
- **半透明黑色横幅**：位于屏幕顶部中央，不影响其他应用使用
- **绿色粗体文字**：清晰易读，支持中文显示
- **自适应横幅长度**：根据文本内容自动调整宽度
- **鼠标拖动功能**：可拖动横幅到任意位置
- **右键退出菜单**：方便关闭程序
- **1秒数据刷新**：实时显示系统状态
- **高分辨率支持**：在高分屏上文字清晰无模糊
- **无第三方库**：仅使用标准C++和Windows API
- **单文件编译**：简洁的源代码结构

## 安装说明

### 方法一：直接运行可执行文件
1. 下载 `monitor.exe` 文件
2. 双击运行即可

### 方法二：从源代码编译
1. 确保已安装MinGW或其他C++编译器
2. 下载源代码文件 `monitor.cpp` 和编译脚本 `compile.ps1`
3. 运行编译脚本生成可执行文件

## 使用方法

1. **启动软件**：双击 `monitor.exe` 或在命令行中执行 `.\monitor.exe`
2. **拖动横幅**：鼠标左键按住横幅拖动到任意位置
3. **退出软件**：右键点击横幅，选择"退出"选项
4. **查看数据**：软件会自动每秒刷新一次系统数据

## 编译步骤

### Windows系统（使用PowerShell）
1. 打开PowerShell终端
2. 导航到源代码目录
3. 运行编译脚本：
   ```powershell
   .\compile.ps1
   ```
4. 编译成功后，会生成 `monitor.exe` 文件

### 手动编译
如果没有PowerShell，可以手动执行编译命令：

```bash
g++ -std=c++11 monitor.cpp -o monitor.exe -lgdiplus -lpsapi -lpdh -liphlpapi -lole32 -loleaut32 -lwbemuuid -lgdi32 -mwindows
```

## 技术实现

### 核心技术
- **Windows API**：窗口创建、分层窗口、透明度设置
- **GDI/GDI+**：文本渲染、字体设置、双缓冲技术
- **PDH (Performance Data Helper)**：CPU使用率监控
- **WMI (Windows Management Instrumentation)**：硬件信息获取
- **多线程**：后台数据采集线程，避免UI卡顿
- **DPI感知**：支持高分辨率屏幕
- **错误处理**：完善的异常捕获和超时机制

### 主要功能模块
- **getCPUUsage()**：使用PDH API获取CPU使用率
- **getCPUTemperature()**：使用WMI获取CPU温度，支持多种温度单位转换
- **getCPUFrequency()**：使用Performance Counter API获取动态睿频频率
- **getMemoryUsage()**：使用GlobalMemoryStatusEx获取内存使用情况
- **getNetworkSpeed()**：使用Windows API获取网络速度
- **formatSpeed()**：格式化网络速度单位
- **DataCollectionThread()**：后台数据采集线程，包含超时机制
- **WndProc()**：窗口过程，处理UI事件
- **WinMain()**：主入口点

## 注意事项

1. **权限要求**：部分系统信息（如CPU温度）可能需要管理员权限才能获取
2. **GPU支持**：当前仅支持NVIDIA显卡的详细信息（通过nvidia-smi）
3. **网络速度**：首次启动后可能需要几秒钟才能稳定显示网络速度
4. **系统兼容性**：支持Windows 7及以上版本
5. **性能影响**：软件设计轻量，对系统性能影响极小

## 常见问题

### Q: 运行后没有看到横幅？
A: 请检查任务管理器中是否有monitor.exe进程，如果有，可能是横幅被其他窗口遮挡，尝试拖动其他窗口查看。

### Q: CPU温度显示为0？
A: 可能是因为你的CPU不支持通过WMI获取温度，或者需要管理员权限。

### Q: 网络速度显示不准确？
A: 网络速度计算需要累积数据，首次启动后需要几秒钟才能稳定显示。

### Q: 高分辨率屏幕上文字模糊？
A: 软件已实现DPI感知，在高分屏上应该显示清晰。如果仍然模糊，请检查系统显示设置。

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 作者

使用C++和Windows API开发

---

**免责声明**：本软件仅供个人使用，作者不对因使用本软件而导致的任何问题负责。
