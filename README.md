# Cyberspace-anomaly-perception-system
2020-基于日志的分布式网络空间异常感知系统
===================================
    由于此项目还在初级阶段，需要不断完善，建议仅用于参考学习和二次开发
系统思路
----
主要是假定网络攻击场景，思考入侵会在哪些设备上留下记录，分析记录元素，将有关联的元素提取出来，作为这个攻击场景的关联搜索条件之一。

**技术层面**主要是使用python的paramiko作为SSH隧道远程执行命令，配合bash和powershell脚本达到实时监控的功能，然后使用数据分析模块对监控的日志数据进行分析，最后再使用关联分析模块辅助报警。

**相关技术**web是用的flask框架（因为想快点做完，所以用了轻量级框架），前端bulma等、后端是bash脚本、powershell脚本、python脚本等，使用bash和powershell主要是更方便对底层的系统的交互。

功能介绍
----
* 目标登陆行为监控
* 目标主机敏感操作监控
* 安全设备日志监控
* 服务器资源监控
* 内部用户管理
以上功能在windows端和linux端都有各自的实现，方式不同，效果略有差异。
# 系统架构一览
![image](https://github.com/a13202026257/Cyberspace-anomaly-perception-system/blob/master/jpg/jiagou.png)

# windows端的实现流程图
    linux的实现图比较简单就不放了
![image](https://github.com/a13202026257/Cyberspace-anomaly-perception-system/blob/master/jpg/denglu-windows.png)

测试效果
-----
![image](https://github.com/a13202026257/Cyberspace-anomaly-perception-system/blob/master/jpg/control.png)
![image](https://github.com/a13202026257/Cyberspace-anomaly-perception-system/blob/master/jpg/dashboard.png)
![image](https://github.com/a13202026257/Cyberspace-anomaly-perception-system/blob/master/jpg/result.png)

PS
---
源码plugn中放的是bash，powershell脚本，对应系统中的敏感目录监控，资源用量监控
自己写的，感觉会比较有用处分享一下。

To do
----
* 优化前端的交互，与各功能接口更好对接起来
* 框架迁移django
* 增加Elasticsearch数据查询接口
* windows的登陆日志目前只采集了ssh端口、telnet、3389端口的登陆情况，根据事件ID还可以采集更多的数据
* windows登陆日志由于windows事件日志的更新机制，会滞后，实时性不能保证，问题待解决
* 使用gevent代替threads
* 优化数据采集时的预处理，目前过滤功能较差

