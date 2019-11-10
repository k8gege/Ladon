# Ladon 5.5 20191109

[![Author](https://img.shields.io/badge/Author-k8gege-blueviolet)](https://github.com/k8gege) 
[![Ladon](https://img.shields.io/badge/Ladon-5.5-yellowgreen)](https://github.com/k8gege/Ladon) 
[![Bin](https://img.shields.io/badge/Ladon-Bin-yellowgreen)](https://github.com/k8gege/Ladon/releases) 
[![GitHub issues](https://img.shields.io/github/issues/k8gege/Ladon)](https://github.com/k8gege/Ladon/issues) 
[![Github Stars](https://img.shields.io/github/stars/k8gege/Ladon)](https://github.com/k8gege/Ladon) 
[![GitHub forks](https://img.shields.io/github/forks/k8gege/Ladon)](https://github.com/k8gege/Ladon)
[![GitHub license](https://img.shields.io/github/license/k8gege/Ladon)](https://github.com/k8gege/Ladon)

### 程序演示
<img src=https://k8gege.github.io/k8img/Ladon/Ladon.gif></img>
### Cobalt Strike
<img src=https://k8gege.github.io/k8img/Ladon/CS_Ladon.gif></img>
### 使用说明
https://github.com/k8gege/Ladon/wiki<br>

### 源码编译
git clone https://github.com/k8gege/Ladon.git<br>
使用VS2012或以上版本分别编译.net 3.5、4.0版本EXE<br>

### 成品下载
https://github.com/k8gege/Ladon/releases<br>
Win7/2008或安装.net 2.x 3.x系统可以使用3.5的exe<br>
Win8-win10或安装.net 4.x系统可以使用4.0的exe<br>

### 关于

Ladon是希腊神话中的神兽，看守金苹果的百头巨龙。它从不睡觉，被赫拉克勒斯借扛天巨人之手诱巨龙睡着<br>
杀死巨龙并偷得了金苹果。巨龙死前将自己的魂魄封印在金苹果中，偷盗者将金苹果送给了白雪公主，公主<br>
为了报恩将金苹果分给了七个小矮人，吃下以后他们变成了龙珠散落到世界各地，龙珠分为七颗，它蕴含着<br>
可以令奇迹发生的力量。当集齐7颗龙珠念出咒语，就能召唤神龙，而神龙则会实现召唤者提出的一个愿望。<br>

### 前言

无论内网还是外网渗透信息收集都是非常关键，信息收集越多越准确渗透的成功率就越高。<br>
但成功率还受到漏洞影响，漏洞受时效性影响，对于大型内网扫描速度直接影响着成功率。<br>
漏洞时效性1-2天，扫描内网或外网需1周时间，是否会因此错过很多或许可成功的漏洞？<br>
对于那些拥有几百上千域名的大站来说，你发现越快成功率就越高，慢管理员就打补丁了。<br>
因此我们需要一个支持批量C段/B段甚至A段的扫描器，添加自定义模块快速检测新出漏洞。<br>

### 程序简介

Ladon一款用于大型网络渗透的多线程插件化综合扫描神器，含端口扫描、服务识别、网络资产、密码爆破、高危漏洞检测以及一键GetShell，支持批量A段/B段/C段以及跨网段扫描，支持URL、主机、域名列表扫描。5.5版本内置39个功能模块,通过多种协议以及方法快速获取目标网络存活主机IP、计算机名、工作组、共享资源、网卡地址、操作系统版本、网站、子域名、中间件、开放服务、路由器、数据库等信息，漏洞检测包含MS17010、Weblogic、ActiveMQ、Tomcat、Struts2等，密码爆破11种含数据库(Mysql、Oracle、MSSQL)、FTP、SSH(Linux主机)、VNC、Windows密码(IPC、WMI、SMB)、Weblogic后台、Rar压缩包密码等，Web指纹识别模块可识别75种（Web应用、中间件、脚本类型、页面类型）等，可高度自定义插件POC支持.NET程序集、DLL(C#/Delphi/VC)、PowerShell等语言编写的插件,支持通过配置INI批量调用任意外部程序或命令，EXP生成器可一键生成漏洞POC快速扩展扫描能力。Ladon支持Cobalt Strike插件化扫描快速拓展内网进行横向移动。<br>

### 使用简单

虽然Ladon功能丰富多样,但使用却非常简单,任何人都能轻易上手<br>
只需一或两个参数就可用90%的功能,一个模块相当于一个新工具<br>

### 运行环境

Ladon.exe可在安装有.net 2.0及以上版本Win系统中使用(Win7后系统自带.net)<br>
如Cmd、PowerShell、远控Cmd、WebShell等，以及Cobalt Strike内存加载使用<br>

### 奇葩条件

实战并不那么顺利，有些内网转发后很卡或无法转发，只能将工具上传至目标<br>
有些马可能上传两三M的程序都要半天甚至根本传不了，PY的几十M就更别想了<br>
Ladon采用C#研发，程序体积很小500K左右，即便马不行也能上传500K程序吧<br>
还不行也可PowerShell远程内存加载,这点是PY或GO编译的大程序无法比拟的<br>

### 宗旨

为用户提供一个简单易用、功能丰富、高度灵活、可定制的扫描工具，减少大量重复操作提高工作效率<br>

### 程序参数功能

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
23 支持自定义模块(支持多种语言编写的DLL/.NET程序集/PowerShell脚本)<br>
24 支持Cobalt Strike(beacon命令行下扫描目标内网或跳板扫描外网目标)<br>

### 内置功能模块(39)

#### 0x001 资产扫描<br>

例子: Ladon OnlinePC(扫当前机器所处C段，其它模块同理)<br>
例子: Ladon 192.168.1.8/24 OnlinePC<br>

1  OnlinePC 		存活主机扫描<br>
2  OnlineIP 		仅存活主机IP<br>
3  UrlScan 			URL域名扫描<br>
4  SameWeb 			同服域名扫描<br>
5  WebScan 			Web信息扫描<br>
6  WebDir 			后台目录扫描<br>
7  SubDomain 		子域名爆破<br>
8  DomainIP 		域名解析IP	<br>
9  HostIP 			主机名转IP<br>

#### 0x002 指纹识别/服务识别<br>

例子: Ladon OsScan<br>
例子: Ladon 192.168.1.8/24 OsScan<br>

1  OsScan 			操作系统版本探测<br>
2  PortScan 		端口扫描含Banner<br>
3  WebBanner 		内网Web信息扫描<br>
4  WhatCMS 			75种Web指纹识别<br>
5  CiscoScan 		思科设备扫描<br>
6  EnumMssql 		枚举Mssql数据库主机<br>
7  EnumShare 		枚举网络共享资源<br>

#### 0x003 口令检测/密码爆破<br>
[自定义端口(IP:端口)、帐密检测(用户 密码)、主机帐密检测(IP 端口 数据库 用户 密码)]<br>

例子: Ladon SshScan<br>
例子: Ladon 192.168.1.8/24 SshScan<br>
例子: Ladon 192.168.1.8:22 SshScan (指定端口)<br>
例子: Ladon test.rar RarScan<br>

1  WmiScan 			Wmi密码爆破(Windowns)<br>
2  IpcScan 			Ipc密码爆破(Windows)<br>
3  SmbScan 			SMB密码爆破(Windows)<br>
4  SshScan 			SSH密码爆破(Linux)<br>
5  MssqlScan 		Mssql数据库密码爆破<br>
6  OracleScan 		Oracle数据库密码爆破<br>
7  MysqlScan 		Mysql数据库密码爆破<br>
8  WeblogicScan 	Weblogic后台密码爆破<br>
9  VncScan 			VNC远程桌面密码爆破<br>
10 FtpScan 			Ftp服务器密码爆破<br>
11 RarScan 			Rar压缩包密码爆破	<br>

#### 0x004 漏洞检测/漏洞利用

例子: Ladon MS17010<br>
例子: Ladon 192.168.1.8/24 MS17010<br>
例子: Ladon http://192.168.1.8 WeblogicExp<br>

1  MS17010 			SMB漏洞检测(CVE-2017-0143/CVE-2017-0144/CVE-2017-0145/CVE-2017-0146/CVE-2017-0148)<br>
2  WeblogicPoc		Weblogic漏洞检测(CVE-2019-2725)<br>
3  PhpStudyPoc 		PhpStudy后门检测(phpstudy 2016/phpstudy 2018)<br>
4  ActivemqPoc 		ActiveMQ漏洞检测(CVE-2016-3088)	<br>
5  TomcatPoc 		Tomcat漏洞检测(CVE-2017-12615)<br>
6  WeblogicExp		Weblogic漏洞利用(CVE-2019-2725)<br>
7  TomcatExp 		Tomcat漏洞利用(CVE-2017-12615)<br>
8  Struts2Poc		Struts2漏洞检测(S2-005/S2-009/S2-013/S2-016/S2-019/S2-032/DevMode)<br>

#### 0x006 加密解密
例子: Ladon 字符串 EnHex<br>
例子: Ladon EnHex (批量str.txt)<br>

1  EnHex			批量Hex密码加密<br>
2  DeHex 			批量Hex密码解密<br>
3  EnBase64			批量Base64密码加密<br>
4  DeBase64 		批量Base64密码解密<br>

注：以上仅是该工具内置模块的初级用法，外置插件或更高级用法请查看使用文档<br>
	中级用法INI文件配置调用任意程序、系统命令、各种语言现成EXP的批量利用<br>
	高级用法Exp生成器一键生成Poc，使用各种语言编写插件扩展Ladon扫描能力。<br>

### 外置插件模块(9)

1  漏洞扫描 CVE 2019-0708 Windows Rdp 3389远程代码执行<br>
2  漏洞利用 ThinkPHP 5.0.22 5.1.29 RCE GetShell Exploit<br>
3  漏洞利用 CVE-2019-9621 Zimbra GetShell Exploit<br>
4  漏洞利用 CVE-2019-0604 SharePoint GetShell Exploit<br>
5  漏洞利用 CVE 2016-3088 ActiveMQ GetShell Exploit<br>
6  漏洞利用 Apache Solr 8.2.0 Velocity RCE 0day Exploit<br>
7  漏洞利用 PhpStudy后门 GetShell Exploit<br>
8  INI调用外部程序命令 批量SSH上控<br>
9  INI调用外部程序命令 批量Win上控<br>
