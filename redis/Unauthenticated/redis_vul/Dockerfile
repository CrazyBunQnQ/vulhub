FROM redis:5.0.7

USER root

# 替换镜像源
RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak && \
    sed -i 's#deb.debian.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#archive.ubuntu.com#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#security.debian.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    sed -i 's#security.ubuntu.com#mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list && \
    apt-get update

RUN apt-get install -y net-tools openssh-server && \
    mkdir /run/sshd && \
    sed -i "s/^#PermitRootLogin.*/PermitRootLogin yes/g" /etc/ssh/sshd_config && \
    sed -i "s/#PasswordAuthentication.*/PasswordAuthentication yes/g" /etc/ssh/sshd_config

RUN echo 'root:password' | chpasswd

EXPOSE 22

#ENTRYPOINT ["redis-server"]