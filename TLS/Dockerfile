# 基于官方 Python 镜像
FROM python:3.12

# 设置工作目录
WORKDIR /app

# 复制当前目录内容到容器
COPY . .

# 安装依赖
RUN pip install pycryptodome gmpy2

# 运行脚本
CMD ["python", "A to B .py"]
