![Ladon](https://k8gege.org/k8img/Ladon/Dragon.jpg)

[![Author](https://img.shields.io/badge/Author-k8gege-blueviolet)](https://github.com/k8gege) [![Ladon](https://img.shields.io/badge/Ladon-5.8-yellowgreen)](https://github.com/k8gege/Ladon) [![Bin](https://img.shields.io/badge/Ladon-Bin-ff69b4)](https://github.com/k8gege/Ladon/releases) [![GitHub issues](https://img.shields.io/github/issues/k8gege/Ladon)](https://github.com/k8gege/Ladon/issues) [![Github Stars](https://img.shields.io/github/stars/k8gege/Ladon)](https://github.com/k8gege/Ladon) [![GitHub forks](https://img.shields.io/github/forks/k8gege/Ladon)](https://github.com/k8gege/Ladon)[![GitHub license](https://img.shields.io/github/license/k8gege/Ladon)](https://github.com/k8gege/Ladon)

### 测试环境 
Kali 2019.4 x64
Ubuntu 18.04 x64

### 安装mono
linux下需mono运行环境，Kali和Ubuntu安装命令通用。
其它系统未进行测试，喜欢用其它Linux系统自行测试。
```Bash
apt install mono-runtime
```

### 运行Ladon
```Bash
mono Ladon OnlinePC
```

### 可用功能
由于mono的兼容性问题，不保证Linux下所有功能均可用
就对于Ladon功能的测试来看Kali的兼容性要比Ubuntu好
测试发现有些功能的稳定性以及速度没有Windows系统快
未列功能系未测试或暂不可用功能，使用前请先看说明
在Kali 2019.4下测试，Ladon支持以下所列的27种功能
=============================================

ID | 模块 |  说明 
-|-|-
1 | WebDir | Web目录扫描
2 | UrlScan | URL域名扫描（不验IP）
3 | PhpStudyPoc | PhpStudy后门扫描
4 | WebScan | Web信息扫描
5 | MysqlScan | Mysql口令检测
6 | OracleScan | Oracle口令检测
7 | VncScan | Vnc口令检测
8 | HttpDownLoad | Http下载
9 | FtpDownLoad | Ftp下载
10 | WhatCMS | 75种CMS识别
11 | FtpScan | Ftp口令检测
12 | PortScan | PortScan端口扫描
13 | SmbScan | Smb口令检测
14 | SameWeb | 站点域名扫描（验证IP）
15 | MS17010 | MS17010漏洞扫描
16 | OnlinePC | 存活主机扫描
17 | OnlineIP | 存活主机IP扫描
18 | HostIP | 主机名解析IP
19 | DomainIP | 子域名解析IP
20 | EnBase64 | 批量Base64密码加密
21 | DeBase64 | 批量Base64密码解密
22 | EnHex | 批量Hex密码加密
23 | DeHex | 批量Hex密码解密
24 | OsScan | 系统版本探测
25 | SubDomain | 子域名爆破
26 | SshScan | SSH口令检测
27 | *.ps1 | 无PowerShell执行脚本

### 暂不支持功能
=============================================
Struts2Poc  X不支持
TomcatScan X不支持
HttpBasicScan X不支持，只能检测是否401认证URL，无法爆破
WeblogicPoc X 竟然不支持(Win下mono也不支持，显然mono问题)
MssqlScan X不支持只能扫到开放端口
IpcScan X不支持(因为调用cmd命令)


### MS17010漏洞扫描
![](https://k8gege.org/k8img/Ladon/kali/Kali_MS17010.gif)

### PortScan端口扫描
![](https://k8gege.org/k8img/Ladon/kali/Kali_PortScan.gif)

### 存活主机扫描
![](https://k8gege.org/k8img/Ladon/kali/Kali_OnlinePC.gif)

### 存活主机IP扫描
可能IP需要用于其它用途，故提供只输出IP功能
![](https://k8gege.org/k8img/Ladon/kali/Kali_OnlineIP.gif)

### Ftp口令检测
![](https://k8gege.org/k8img/Ladon/kali/Kali_FtpScan.gif)

### Smb口令检测
![](https://k8gege.org/k8img/Ladon/kali/Kali_SmbScan.gif)

### 75种CMS识别
![](https://k8gege.org/k8img/Ladon/kali/Kali_WhatCMS.gif)

### 子域名爆破
![](https://k8gege.org/k8img/Ladon/kali/Kali_SubDomain.gif)

### 系统版本探测
![](https://k8gege.org/k8img/Ladon/kali/Kali_OsScan.gif)

### 主机名解析IP
![](https://k8gege.org/k8img/Ladon/kali/Kali_HostIP.gif)

### 子域名解析IP
![](https://k8gege.org/k8img/Ladon/kali/Kali_DomainIP.gif)

### SSH口令检测
![](https://k8gege.org/k8img/Ladon/kali/Kali_SshScan.gif)

### 加载PowerShell插件
![](https://k8gege.org/k8img/Ladon/kali/kali_ps1.PNG)

### PhpStudy后门扫描
![](https://k8gege.org/k8img/Ladon/kali/kali_PhpStudyPoc.gif)

### URL域名扫描（不验IP）
![](https://k8gege.org/k8img/Ladon/kali/kali_UrlScan.gif)

### 站点域名扫描（验证IP）
![](https://k8gege.org/k8img/Ladon/kali/kali_SameWeb.gif)

### Web信息扫描
![](https://k8gege.org/k8img/Ladon/kali/kali_WebScan.gif)

### Web目录扫描
![](https://k8gege.org/k8img/Ladon/kali/kali_WebDir.gif)

### Mysql口令检测
![](https://k8gege.org/k8img/Ladon/kali/kali_MysqlScan.gif)

### Oracle口令检测
![](https://k8gege.org/k8img/Ladon/kali/kali_OracleScan.gif)

### Vnc口令检测
![](https://k8gege.org/k8img/Ladon/kali/kali_VncScan.gif)

### Http/Ftp下载
![](https://k8gege.org/k8img/Ladon/kali/kali_Http_Ftp_Download.PNG)

### Base64密码加解密
![](https://k8gege.org/k8img/Ladon/kali/Kali_Base64.gif)

### Hex密码加解密
![](https://k8gege.org/k8img/Ladon/kali/Kali_Hex.gif)

