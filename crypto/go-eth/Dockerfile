FROM golang:1.19-buster

# 替换镜像源
RUN apt-get update && apt-get install -y ca-certificates && \
    cp /etc/apt/sources.list /etc/apt/sources.list.bak && \
    sed -i 's#deb.debian.org#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#archive.ubuntu.com#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#security.debian.org#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#security.ubuntu.com#mirrors.aliyun.com#g' /etc/apt/sources.list && \
    sed -i 's#http:#https:#g' /etc/apt/sources.list && apt-get update
# 基础工具
RUN apt-get install -y net-tools iputils-ping wget curl
# 依赖
RUN apt-get install -y git make gcc musl-dev
RUN git clone --depth 1 --branch release/1.11 https://github.com/ethereum/go-ethereum.git
RUN cd go-ethereum && make all

# 攻击脚本
RUN cp /go/go-ethereum/build/bin/* /usr/local/bin/

WORKDIR "/opt"

ENV coinbase=""
ENV datadir=""

CMD exec geth --datadir ./$datadir --mine --miner.threads=1 --miner.etherbase=$coinbase --password .passwd

EXPOSE 8545
EXPOSE 30303
#EXPOSE 8551
#EXPOSE 49900

CMD ["sleep", "infinity"]
