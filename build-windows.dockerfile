FROM ubuntu:18.04
RUN apt-get update && apt-get install -y build-essential mingw-w64 cmake unzip git
WORKDIR /app
COPY . .
ENTRYPOINT ["./entrypoint.sh"]
