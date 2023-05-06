FROM ubuntu:18.04

# 替换镜像源
RUN apt-get update && apt-get install -y ca-certificates && \
    cp /etc/apt/sources.list /etc/apt/sources.list.bak && \
    sed -i 's#deb.debian.org#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#archive.ubuntu.com#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#security.debian.org#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#security.ubuntu.com#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#http:#https:#g' /etc/apt/sources.list && apt-get -y update
# Install dependencies
# RUN apt-get install -y git python3 python3-pip net-tools masscan iputils-ping libpcap-dev openssh-client php
# RUN pip3 install requests -i https://mirrors.aliyun.com/pypi/simple/ && \
    # git clone https://github.com/ambionics/phpggc.git
# COPY exploit.py .

CMD ["sleep", "infinity"]