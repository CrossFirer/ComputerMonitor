#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <pdh.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <objidl.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
#include <comdef.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#include <winreg.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#define REFRESH_INTERVAL 2 // 约60FPS的刷新频率

// 定义从LPARAM中提取鼠标坐标的宏
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#endif

#ifndef GET_Y_LPARAM
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

// 确保程序被编译为Windows应用程序，不显示命令行窗口
#pragma comment(linker, "/subsystem:windows /entry:WinMainCRTStartup")

// 启用DPI感知
#if defined(_MSC_VER)
#pragma comment(linker, "-manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

// DPI感知函数已经通过windows.h头文件包含

// 配置项
#define MIN_WINDOW_WIDTH 1050  // 最小窗口宽度
#define WINDOW_MARGIN 60      // 窗口边距

// 全局变量
HINSTANCE g_hInstance;
HWND g_hWnd;
ULONG_PTR gdiplusToken = 0;

// 数据采集相关
std::mutex g_dataMutex;
wchar_t g_monitorData[512] = L"数据获取中，等着。。。。。。";
bool g_dataThreadRunning = false;
std::atomic<bool> g_shouldExit(false);

// CPU监控的PDH句柄
PDH_HQUERY g_pdhQuery = nullptr;
PDH_HCOUNTER g_pdhCounter = nullptr;
bool g_pdhInitialized = false;

// CPU温度和GPU信息的WMI
IWbemLocator* g_pLoc = nullptr;
IWbemServices* g_pSvc = nullptr;
bool g_wmiInitialized = false;

// GPU厂商检测和API
enum GPUVendor {
    GPU_VENDOR_UNKNOWN,
    GPU_VENDOR_NVIDIA,
    GPU_VENDOR_AMD,
    GPU_VENDOR_INTEL
} g_gpuVendor = GPU_VENDOR_UNKNOWN;

// GPU信息结构体
struct GPUInfo {
    float usage;
    float temp;
    float usedGB;
    float totalGB;
} g_gpuInfo = {0};

// 初始化PDH用于CPU使用率监控
static bool initializePDH() {
    if (g_pdhInitialized) {
        return true;
    }

    PDH_STATUS status = PdhOpenQuery(nullptr, 0, &g_pdhQuery);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    status = PdhAddCounterW(g_pdhQuery, L"\\Processor(_Total)\\% Processor Time", 0, &g_pdhCounter);
    if (status != ERROR_SUCCESS) {
        PdhCloseQuery(g_pdhQuery);
        g_pdhQuery = nullptr;
        return false;
    }

    status = PdhCollectQueryData(g_pdhQuery);
    if (status != ERROR_SUCCESS) {
        PdhCloseQuery(g_pdhQuery);
        g_pdhQuery = nullptr;
        return false;
    }

    g_pdhInitialized = true;
    return true;
}

// 清理PDH
static void cleanupPDH() {
    if (g_pdhQuery) {
        PdhCloseQuery(g_pdhQuery);
        g_pdhQuery = nullptr;
    }
    g_pdhCounter = nullptr;
    g_pdhInitialized = false;
}

// 使用PDH API获取CPU使用率
static float getCPUUsage() {
    if (!g_pdhInitialized) {
        if (!initializePDH()) {
            return 0.0f;
        }
    }

    PDH_STATUS status = PdhCollectQueryData(g_pdhQuery);
    if (status != ERROR_SUCCESS) {
        return 0.0f;
    }

    DWORD dwType = 0;
    PDH_FMT_COUNTERVALUE counterValue;
    status = PdhGetFormattedCounterValue(g_pdhCounter, PDH_FMT_DOUBLE, &dwType, &counterValue);
    if (status != ERROR_SUCCESS) {
        return 0.0f;
    }

    return static_cast<float>(counterValue.doubleValue);
}

// 使用WMI获取CPU温度
static float getCPUTemperature() {
    float temp = 0.0f;

    try {
        if (!g_wmiInitialized) {
            HRESULT hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (FAILED(hres)) {
                return 0.0f;
            }

            hres = CoInitializeSecurity(
                nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr
            );
            if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
                CoUninitialize();
                return 0.0f;
            }

            hres = CoCreateInstance(
                CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&g_pLoc
            );
            if (FAILED(hres)) {
                CoUninitialize();
                return 0.0f;
            }

            hres = g_pLoc->ConnectServer(
                SysAllocString(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                0, nullptr, nullptr, &g_pSvc
            );
            if (FAILED(hres)) {
                g_pLoc->Release();
                CoUninitialize();
                return 0.0f;
            }

            hres = CoSetProxyBlanket(
                g_pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE
            );
            if (FAILED(hres)) {
                g_pSvc->Release();
                g_pLoc->Release();
                CoUninitialize();
                return 0.0f;
            }

            g_wmiInitialized = true;
        }

        std::vector<std::wstring> wmiClasses = {
            L"Win32_PerfFormattedData_Counters_ThermalZoneInformation",
            L"MSAcpi_ThermalZoneTemperature",
            L"Win32_TemperatureProbe",
            L"Win32_Processor",
            L"Win32_PerfRawData_Counters_ThermalZoneInformation"
        };

        for (const auto& className : wmiClasses) {
            IEnumWbemClassObject* pEnumerator = nullptr;
            std::wstring query = L"SELECT * FROM " + className;
            HRESULT hres = g_pSvc->ExecQuery(
                SysAllocString(L"WQL"),
                SysAllocString(query.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnumerator
            );

            if (SUCCEEDED(hres)) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;

                while (pEnumerator) {
                    hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (uReturn == 0) {
                        break;
                    }

                    std::vector<std::wstring> tempProperties = {
                        L"Temperature",
                        L"CurrentTemperature",
                        L"Reading",
                        L"CPUtemperature",
                        L"CpuTemperature",
                        L"ProcessorTemperature"
                    };

                    for (const auto& propName : tempProperties) {
                        VARIANT vtProp;
                        hres = pclsObj->Get(propName.c_str(), 0, &vtProp, nullptr, nullptr);
                        if (SUCCEEDED(hres)) {
                            if (vtProp.vt == VT_I4) {
                                if (vtProp.lVal > 2000) {
                                    // MSAcpi_ThermalZoneTemperature 返回的是十分之一开尔文
                                    temp = (float)((vtProp.lVal - 2732) / 10.0);
                                } else if (vtProp.lVal > 273 && vtProp.lVal < 400) {
                                    // 可能是开尔文单位
                                    temp = (float)(vtProp.lVal - 273.15);
                                } else if (vtProp.lVal > 0 && vtProp.lVal < 1000) {
                                    // 可能是十分之摄氏度
                                    temp = (float)(vtProp.lVal / 10.0);
                                } else if (vtProp.lVal > -273 && vtProp.lVal < 200) {
                                    // 直接返回摄氏度
                                    temp = (float)vtProp.lVal;
                                }
                            } else if (vtProp.vt == VT_R4) {
                                if (vtProp.fltVal > -273 && vtProp.fltVal < 200) {
                                    temp = vtProp.fltVal;
                                }
                            } else if (vtProp.vt == VT_R8) {
                                if (vtProp.dblVal > -273 && vtProp.dblVal < 200) {
                                    temp = (float)vtProp.dblVal;
                                }
                            }

                            // 检查温度是否合理（-20到150度之间）
                            if (temp > -20.0f && temp < 150.0f) {
                                VariantClear(&vtProp);
                                pclsObj->Release();
                                pEnumerator->Release();
                                return temp;
                            }

                            VariantClear(&vtProp);
                        }
                    }

                    pclsObj->Release();
                }

                pEnumerator->Release();
            }
        }
    } catch (...) {
        // 防止异常导致函数崩溃
    }

    return temp;
}

// 使用Windows API获取CPU频率（动态睿频频率）
static double getCPUFrequency() {
    double cpuFreq = 0.0;
    
    try {
        // 使用Performance Counter API获取CPU频率
        // 此方法是任务管理器使用的方法，非常准确
        
        // 初始化PDH用于CPU频率监控
        PDH_HQUERY pdhQuery = nullptr;
        PDH_HCOUNTER pdhCounter = nullptr;
        
        if (PdhOpenQuery(nullptr, 0, &pdhQuery) == ERROR_SUCCESS) {
            // 尝试获取处理器频率计数器
            if (PdhAddCounterW(pdhQuery, L"\\Processor Information(_Total)\\% Processor Performance", 0, &pdhCounter) == ERROR_SUCCESS) {
                // 收集初始数据
                PdhCollectQueryData(pdhQuery);
                
                // 等待片刻以获得准确的测量
                Sleep(50);
                
                // 再次收集数据
                if (PdhCollectQueryData(pdhQuery) == ERROR_SUCCESS) {
                    DWORD dwType = 0;
                    PDH_FMT_COUNTERVALUE counterValue;
                    if (PdhGetFormattedCounterValue(pdhCounter, PDH_FMT_DOUBLE, &dwType, &counterValue) == ERROR_SUCCESS) {
                        // 从注册表获取最大CPU频率
                        double maxFreq = 0.0;
                        HKEY hKey;
                        DWORD dwTypeReg, dwSize;
                        DWORD cpuMHz = 0;
                        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                            dwSize = sizeof(DWORD);
                            if (RegQueryValueEx(hKey, "~MHz", nullptr, &dwTypeReg, (LPBYTE)&cpuMHz, &dwSize) == ERROR_SUCCESS && dwTypeReg == REG_DWORD) {
                                maxFreq = cpuMHz / 1000.0;
                            }
                            RegCloseKey(hKey);
                        }
                        
                        // 根据性能百分比计算当前频率
                        if (maxFreq > 0.0) {
                            cpuFreq = (counterValue.doubleValue / 100.0) * maxFreq;
                        }
                    }
                }
                PdhRemoveCounter(pdhCounter);
            }
            PdhCloseQuery(pdhQuery);
        }
        
        // 验证结果（应该在0.5GHz和10.0GHz之间）
        if (cpuFreq < 0.5 || cpuFreq > 10.0) {
            // 如果Performance Counter失败，回退到注册表
            HKEY hKey;
            DWORD dwType, dwSize;
            DWORD cpuMHz = 0;
            
            // 尝试从注册表获取CPU频率
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                dwSize = sizeof(DWORD);
                if (RegQueryValueEx(hKey, "~MHz", nullptr, &dwType, (LPBYTE)&cpuMHz, &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD) {
                    cpuFreq = cpuMHz / 1000.0;
                }
                RegCloseKey(hKey);
            }
        }
    } catch (...) {
        // 防止异常导致函数崩溃
    }
    
    return cpuFreq;
}

// 使用GlobalMemoryStatusEx获取内存使用情况
static std::tuple<float, float, float> getMemoryUsage() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    DWORDLONG totalPhysMem = memInfo.ullTotalPhys;
    DWORDLONG availPhysMem = memInfo.ullAvailPhys;
    DWORDLONG usedPhysMem = totalPhysMem - availPhysMem;

    float memUsage = (float)usedPhysMem / totalPhysMem * 100.0f;
    float memUsedGB = (float)usedPhysMem / (1024.0f * 1024.0f * 1024.0f);
    float memTotalGB = (float)totalPhysMem / (1024.0f * 1024.0f * 1024.0f);

    return { memUsage, memUsedGB, memTotalGB };
}

// 运行外部命令并捕获输出（不显示控制台窗口）
static std::string runCommand(const char* cmd) {
    std::string result;
    char buffer[4096] = {0};
    
    try {
        PROCESS_INFORMATION pi;
        STARTUPINFOA si;
        SECURITY_ATTRIBUTES sa;
        
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;
        
        HANDLE hStdOutRead, hStdOutWrite;
        if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
            return result;
        }
        
        ZeroMemory(&si, sizeof(STARTUPINFOA));
        si.cb = sizeof(STARTUPINFOA);
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdOutWrite;
        si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        if (CreateProcessA(
            NULL, (LPSTR)cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        )) {
            WaitForSingleObject(pi.hProcess, 1000);
            
            CloseHandle(hStdOutWrite);
            
            DWORD bytesRead;
            while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                result += buffer;
            }
            
            CloseHandle(hStdOutRead);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            CloseHandle(hStdOutRead);
            CloseHandle(hStdOutWrite);
        }
    } catch (...) {
        // 防止异常导致函数崩溃
    }
    
    return result;
}

// 检测GPU厂商
static void detectGPUVendor() {
    if (g_gpuVendor != GPU_VENDOR_UNKNOWN) {
        return;
    }

    try {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\NVIDIA Corporation\\Installer", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_gpuVendor = GPU_VENDOR_NVIDIA;
            return;
        }

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_gpuVendor = GPU_VENDOR_NVIDIA;
            return;
        }

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\AMD", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_gpuVendor = GPU_VENDOR_AMD;
            return;
        }

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\amdkmdag", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_gpuVendor = GPU_VENDOR_AMD;
            return;
        }

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Intel\\Graphics", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_gpuVendor = GPU_VENDOR_INTEL;
            return;
        }

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\igfx", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_gpuVendor = GPU_VENDOR_INTEL;
            return;
        }

        if (GetFileAttributes("C:\\Windows\\System32\\nvidia-smi.exe") != INVALID_FILE_ATTRIBUTES) {
            g_gpuVendor = GPU_VENDOR_NVIDIA;
            return;
        }
    } catch (...) {
        // 防止异常导致函数崩溃
    }

    g_gpuVendor = GPU_VENDOR_UNKNOWN;
}

// 使用厂商特定API更新GPU信息
static void updateGPUInfo() {
    static long long lastUpdate = 0;
    long long currentTime = GetTickCount64();
    if (currentTime - lastUpdate < 2000) {
        return;
    }

    try {
        if (g_gpuVendor == GPU_VENDOR_UNKNOWN) {
            detectGPUVendor();
        }

        std::string output;
        switch (g_gpuVendor) {
        case GPU_VENDOR_NVIDIA:
            output = runCommand("nvidia-smi --query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total --format=csv,noheader,nounits");
            if (!output.empty()) {
                output.erase(std::remove_if(output.begin(), output.end(), ::isspace), output.end());
                
                std::istringstream ss(output);
                std::string token;
                std::vector<float> values;
                
                while (std::getline(ss, token, ',')) {
                    try {
                        values.push_back(std::stof(token));
                    } catch (...) {
                        values.push_back(0.0f);
                    }
                }
                
                if (values.size() >= 4) {
                    g_gpuInfo.usage = values[0];
                    g_gpuInfo.temp = values[1];
                    g_gpuInfo.usedGB = values[2] / 1024.0f;
                    g_gpuInfo.totalGB = values[3] / 1024.0f;
                }
            }
            break;

        default:
            break;
        }
    } catch (...) {
        // 防止异常导致函数崩溃
    }

    lastUpdate = currentTime;
}

static float getGPUUsage() {
    updateGPUInfo();
    return g_gpuInfo.usage;
}

static float getGPUTemperature() {
    updateGPUInfo();
    return g_gpuInfo.temp;
}

static std::pair<float, float> getGPUMemory() {
    updateGPUInfo();
    return { g_gpuInfo.usedGB, g_gpuInfo.totalGB };
}

// 使用Windows API获取网络速度
static std::pair<float, float> getNetworkSpeed() {
    static long long lastTime = 0;
    static DWORD lastSendBytes = 0;
    static DWORD lastRecvBytes = 0;
    
    long long currentTime = GetTickCount64();
    if (currentTime - lastTime < 2000) {
        return { 0.0f, 0.0f };
    }

    DWORD sendBytes = 0;
    DWORD recvBytes = 0;

    try {
        PMIB_IFTABLE ifTable = nullptr;
        DWORD dwSize = 0;
        DWORD result = GetIfTable(ifTable, &dwSize, FALSE);
        if (result == ERROR_INSUFFICIENT_BUFFER) {
            ifTable = (PMIB_IFTABLE)malloc(dwSize);
            if (ifTable != nullptr) {
                result = GetIfTable(ifTable, &dwSize, FALSE);
                if (result == NO_ERROR) {
                    for (DWORD i = 0; i < ifTable->dwNumEntries; i++) {
                        MIB_IFROW& ifRow = ifTable->table[i];
                        if (ifRow.dwAdminStatus == MIB_IF_ADMIN_STATUS_UP && 
                            ifRow.dwType != IF_TYPE_SOFTWARE_LOOPBACK) {
                            sendBytes += ifRow.dwOutOctets;
                            recvBytes += ifRow.dwInOctets;
                        }
                    }
                }
                free(ifTable);
            }
        }
    } catch (...) {
        // 防止异常导致函数崩溃
    }

    float sendSpeed = 0.0f;
    float recvSpeed = 0.0f;

    if (lastTime > 0 && lastSendBytes > 0 && lastRecvBytes > 0) {
        double elapsedSeconds = (currentTime - lastTime) / 1000.0;
        if (elapsedSeconds > 0) {
            sendSpeed = static_cast<float>((sendBytes - lastSendBytes) / elapsedSeconds);
            recvSpeed = static_cast<float>((recvBytes - lastRecvBytes) / elapsedSeconds);
        }
    }

    lastTime = currentTime;
    lastSendBytes = sendBytes;
    lastRecvBytes = recvBytes;

    return { sendSpeed, recvSpeed };
}

static std::wstring formatSpeed(float bytesPerSecond) {
    std::wstringstream ss;
    float kbPerSecond = bytesPerSecond / 1024.0f;
    if (kbPerSecond < 1024.0f) {
        ss << std::fixed << std::setprecision(2) << kbPerSecond << L" KB/s";
    }
    else if (kbPerSecond < 1024.0f * 1024.0f) {
        ss << std::fixed << std::setprecision(2) << (kbPerSecond / 1024.0f) << L" MB/s";
    }
    else {
        ss << std::fixed << std::setprecision(2) << (kbPerSecond / (1024.0f * 1024.0f)) << L" GB/s";
    }
    return ss.str();
}

// 移除FPS相关代码

// 数据采集线程函数
static DWORD WINAPI DataCollectionThread(LPVOID lpParam) {
    static int updateCount = 0;
    while (!g_shouldExit) {
        try {
            // 每60次循环（约1秒）更新一次其他监控数据和界面
            if (updateCount % 60 == 0) {
                // 记录开始时间，用于超时检测
                DWORD startTime = GetTickCount();
                
                float cpuUsage = 0.0f;
                if (GetTickCount() - startTime < 50) {
                    cpuUsage = getCPUUsage();
                }
                
                float cpuTemp = 0.0f;
                if (GetTickCount() - startTime < 100) {
                    cpuTemp = getCPUTemperature();
                }
                
                double cpuFreq = 0.0;
                if (GetTickCount() - startTime < 150) {
                    cpuFreq = getCPUFrequency();
                }
                
                float gpuUsage = 0.0f;
                if (GetTickCount() - startTime < 200) {
                    gpuUsage = getGPUUsage();
                }
                
                float gpuTemp = 0.0f;
                if (GetTickCount() - startTime < 250) {
                    gpuTemp = getGPUTemperature();
                }
                
                std::pair<float, float> gpuMem = {0.0f, 0.0f};
                if (GetTickCount() - startTime < 300) {
                    gpuMem = getGPUMemory();
                }
                
                std::tuple<float, float, float> mem = {0.0f, 0.0f, 0.0f};
                if (GetTickCount() - startTime < 350) {
                    mem = getMemoryUsage();
                }
                
                std::pair<float, float> net = {0.0f, 0.0f};
                if (GetTickCount() - startTime < 400) {
                    net = getNetworkSpeed();
                }

                // 格式化输出
                std::wstringstream ss;
                ss << L"CPU " << std::fixed << std::setprecision(1) << cpuUsage << L"% "
                   << std::fixed << std::setprecision(1) << cpuTemp << L"°C "
                   << std::fixed << std::setprecision(2) << cpuFreq << L"GHz "
                   << L"显卡 " << std::fixed << std::setprecision(1) << gpuUsage << L"% "
                   << std::fixed << std::setprecision(1) << gpuTemp << L"°C "
                   << std::fixed << std::setprecision(1) << gpuMem.first << L"GB/" << gpuMem.second << L"GB "
                   << L"内存 " << std::fixed << std::setprecision(1) << std::get<0>(mem) << L"% "
                   << std::fixed << std::setprecision(1) << std::get<1>(mem) << L"GB/" << std::get<2>(mem) << L"GB "
                   << L"网络 ↑ " << formatSpeed(net.first) << L" ↓ " << formatSpeed(net.second);

                // 更新全局数据
                std::lock_guard<std::mutex> lock(g_dataMutex);
                // 简化字符串复制，确保不会导致缓冲区溢出
                std::wstring text = ss.str();
                if (text.empty()) {
                    // 如果文本为空，设置一个默认值
                    text = L"数据获取中，等着。。。。。。";
                }
                // 确保字符串长度不超过缓冲区大小
                size_t maxLength = sizeof(g_monitorData) / sizeof(wchar_t) - 1;
                if (text.length() > maxLength) {
                    text = text.substr(0, maxLength);
                }
                // 复制字符串到全局变量
                wcscpy(g_monitorData, text.c_str());
            }
            
            // 每10次循环（约160毫秒）调整一次窗口大小，确保窗口宽度能及时适应内容变化
            if (updateCount % 10 == 0) {
                // 调整窗口大小，实现真正的自适应宽度
                static int lastWidth = 0;
                if (g_hWnd) {
                    // 创建临时DC来计算文本宽度
                    HDC hdc = GetDC(g_hWnd);
                    if (hdc) {
                        // 创建与窗口相同的字体来计算文本宽度
                        HFONT hFont = CreateFont(
                            12, 0, 0, 0, FW_BOLD,
                            FALSE, FALSE, FALSE, GB2312_CHARSET,
                            OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
                            "Courier New"
                        );
                        
                        if (hFont) {
                            // 选择字体到DC
                            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
                            
                            // 使用选定的字体计算文本宽度
                            SIZE textSize;
                            int textLength = wcslen(g_monitorData);
                            if (textLength > 0) {
                                // 计算文本宽度
                                GetTextExtentPoint32W(hdc, g_monitorData, textLength, &textSize);
                                
                                // 计算窗口宽度，确保足够容纳所有内容
                                int newWidth = textSize.cx + WINDOW_MARGIN; // 使用配置的边距
                                
                                // 确保窗口宽度至少为配置的最小宽度，避免窗口变得太小
                                if (newWidth < MIN_WINDOW_WIDTH) {
                                    newWidth = MIN_WINDOW_WIDTH;
                                }
                                
                                // 只在宽度确实需要改变时才调整窗口大小
                                if (newWidth != lastWidth) {
                                    // 先获取当前窗口位置，保持顶部位置不变
                                    RECT currentRect;
                                    GetWindowRect(g_hWnd, &currentRect);
                                    
                                    // 计算新的窗口X坐标，使其居中显示
                                    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
                                    int newX = (screenWidth - newWidth) / 2;
                                    
                                    // 调整窗口大小和位置
                                    SetWindowPos(g_hWnd, nullptr, newX, currentRect.top, newWidth, 40, SWP_NOZORDER);
                                    lastWidth = newWidth;
                                }
                            }
                            
                            // 恢复旧字体并删除创建的字体
                            SelectObject(hdc, hOldFont);
                            DeleteObject(hFont);
                        }
                        
                        ReleaseDC(g_hWnd, hdc);
                    }
                }
            }
            
            updateCount++;
        } catch (...) {
            // 防止异常导致线程崩溃
            // 即使发生异常，也要增加updateCount，避免无限循环执行同一代码块
            updateCount++;
        }

        // 休眠16毫秒，约60FPS的频率
        Sleep(16);
    }

    return 0;
}

// 窗口过程
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static bool g_isDragging = false;
    static POINT g_lastMousePos = {0, 0};
    static HBRUSH hBrush = nullptr;
    static HFONT hFont = nullptr;
    static int g_dpiScale = 100; // 初始化为100%缩放

    switch (message) {
    case WM_CREATE:
        {
            // 获取系统DPI缩放因子
            HDC hdc = GetDC(hWnd);
            if (hdc) {
                g_dpiScale = GetDeviceCaps(hdc, LOGPIXELSY) * 100 / 96;
                ReleaseDC(hWnd, hdc);
            }
            
            // 创建背景刷（黑色）
            hBrush = CreateSolidBrush(RGB(0, 0, 0));
            
            // 创建字体，根据DPI缩放调整大小
            int fontSize = 12 * g_dpiScale / 100;
            hFont = CreateFont(
                fontSize, 0, 0, 0, FW_BOLD,
                FALSE, FALSE, FALSE, GB2312_CHARSET,
                OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
                "Courier New"
            );
            
            
            
            // 启动数据采集线程
            g_dataThreadRunning = true;
            HANDLE hThread = CreateThread(nullptr, 0, DataCollectionThread, nullptr, 0, nullptr);
            if (hThread) {
                CloseHandle(hThread);
            }
            
            // 设置定时器，用于刷新窗口
            SetTimer(hWnd, 1, REFRESH_INTERVAL, nullptr);
        }
        break;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        try {
            // 获取文本
            std::lock_guard<std::mutex> lock(g_dataMutex);
            std::wstring text = g_monitorData;
            
            // 获取窗口大小
            RECT rect;
            GetClientRect(hWnd, &rect);
            int width = rect.right - rect.left;
            int height = rect.bottom - rect.top;
            
            // 创建双缓冲
            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, width, height);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);
            
            if (memDC && memBitmap) {
                // 绘制背景
                FillRect(memDC, &rect, hBrush);

                // 使用GDI+进行高质量文字渲染
                Gdiplus::Graphics graphics(memDC);
                graphics.SetTextRenderingHint(Gdiplus::TextRenderingHintClearTypeGridFit);
                
                // 创建字体
                int fontSize = 12 * g_dpiScale / 100;
                Gdiplus::Font font(L"Courier New", fontSize, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush brush(Gdiplus::Color(255, 0, 255, 0)); // 绿色文字
                
                // 计算文本位置
                Gdiplus::StringFormat format;
                format.SetAlignment(Gdiplus::StringAlignmentCenter);
                format.SetLineAlignment(Gdiplus::StringAlignmentCenter);
                format.SetTrimming(Gdiplus::StringTrimmingNone);
                format.SetFormatFlags(Gdiplus::StringFormatFlagsNoWrap); // 禁止自动换行
                
                // 绘制文本
                Gdiplus::RectF rectF(0, 0, width, height);
                graphics.DrawString(text.c_str(), -1, &font, rectF, &format, &brush);
                
                // 将双缓冲内容复制到屏幕
                BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);
                
                // 清理双缓冲资源
                SelectObject(memDC, oldBitmap);
                DeleteObject(memBitmap);
                DeleteDC(memDC);
            }
        } catch (...) {
            // 防止异常导致绘制失败
        }
        
        EndPaint(hWnd, &ps);
    }
    break;

    case WM_TIMER:
        // 定时器触发，刷新窗口
        InvalidateRect(hWnd, nullptr, FALSE);
        break;

    case WM_LBUTTONDOWN:
        // 开始拖动
        g_isDragging = true;
        g_lastMousePos.x = GET_X_LPARAM(lParam);
        g_lastMousePos.y = GET_Y_LPARAM(lParam);
        SetCapture(hWnd);
        break;

    case WM_MOUSEMOVE:
        // 拖动窗口
        if (g_isDragging) {
            POINT curPos;
            curPos.x = GET_X_LPARAM(lParam);
            curPos.y = GET_Y_LPARAM(lParam);

            RECT wndRect;
            GetWindowRect(hWnd, &wndRect);

            int dx = curPos.x - g_lastMousePos.x;
            int dy = curPos.y - g_lastMousePos.y;

            SetWindowPos(hWnd, nullptr, wndRect.left + dx, wndRect.top + dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        }
        break;

    case WM_LBUTTONUP:
        // 结束拖动
        if (g_isDragging) {
            g_isDragging = false;
            ReleaseCapture();
        }
        break;

    case WM_RBUTTONDOWN:
        // 显示右键菜单
        {
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, 1, L"退出");

            POINT pos;
            GetCursorPos(&pos);
            TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN, pos.x, pos.y, 0, hWnd, nullptr);
            DestroyMenu(hMenu);
        }
        break;

    case WM_COMMAND:
        // 处理菜单命令
        if (LOWORD(wParam) == 1) {
            // 退出程序
            PostQuitMessage(0);
        }
        break;

    case WM_DESTROY:
        // 清理资源
        KillTimer(hWnd, 1);
        
        // 停止数据采集线程
        g_shouldExit = true;
        Sleep(100); // 等待线程退出
        
        // 清理GDI资源
        if (hBrush) {
            DeleteObject(hBrush);
        }
        if (hFont) {
            DeleteObject(hFont);
        }
        
        // 清理PDH
        cleanupPDH();
        
        // 清理WMI
        if (g_wmiInitialized) {
            if (g_pSvc) {
                g_pSvc->Release();
            }
            if (g_pLoc) {
                g_pLoc->Release();
            }
            CoUninitialize();
        }
        
        // 清理GDI+
        if (gdiplusToken) {
            Gdiplus::GdiplusShutdown(gdiplusToken);
        }
        
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}

// 主函数
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInstance = hInstance;

    // 启用DPI感知，确保在高分辨率屏幕上正确显示
    typedef BOOL (WINAPI *SetProcessDpiAwarenessContextFunc)(DPI_AWARENESS_CONTEXT);
    HMODULE hUser32 = GetModuleHandle("user32.dll");
    SetProcessDpiAwarenessContextFunc pSetProcessDpiAwarenessContext = (SetProcessDpiAwarenessContextFunc)GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
    
    if (pSetProcessDpiAwarenessContext) {
        // Windows 10及以上，使用Per-Monitor DPI感知
        pSetProcessDpiAwarenessContext((DPI_AWARENESS_CONTEXT)-3); // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    } else {
        // 旧版Windows，使用系统DPI感知
        typedef BOOL (WINAPI *SetProcessDPIAwareFunc)();
        SetProcessDPIAwareFunc pSetProcessDPIAware = (SetProcessDPIAwareFunc)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (pSetProcessDPIAware) {
            pSetProcessDPIAware();
        }
    }

    // 初始化GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    // 注册窗口类
    WNDCLASSEX wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = nullptr;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = "MonitorWindow";
    wcex.hIconSm = nullptr;

    if (!RegisterClassEx(&wcex)) {
        MessageBox(nullptr, "窗口类注册失败", "错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 创建窗口
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int x = (screenWidth - 600) / 2;
    int y = 0; // 屏幕最上方

    HWND hWnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
        "MonitorWindow",
        "系统监控",
        WS_POPUP | WS_VISIBLE,
        x, y, 600, 40,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hWnd) {
        MessageBox(nullptr, "窗口创建失败", "错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    g_hWnd = hWnd;

    // 设置窗口半透明
    SetLayeredWindowAttributes(hWnd, 0, 180, LWA_ALPHA);

    // 显示窗口
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 清理GDI+
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return (int)msg.wParam;
}
