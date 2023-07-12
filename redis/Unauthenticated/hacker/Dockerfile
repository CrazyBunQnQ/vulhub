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