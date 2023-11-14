# 使用 Ubuntu 20.04 LTS 作为基础镜像
FROM ubuntu:20.04

# 更换清华源
RUN sed -i 's/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list


RUN apt update 
RUN apt install -y dirmngr wget gnupg apt-transport-https ca-certificates software-properties-common gnupg  
RUN wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -

RUN echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" |  tee /etc/apt/sources.list.d/mongodb-org-6.0.list
RUN apt update
RUN apt install -y mongodb-org
RUN mkdir -p /data/db

EXPOSE 27017

