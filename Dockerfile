FROM alpine:latest as builder
RUN apk update && apk upgrade && apk add --no-cache bash util-linux cmake make gcc git sqlite-dev openssl-dev git build-base
WORKDIR /app
COPY . .
RUN cmake . && make
RUN sed -i 's/\/usr\/lib\/uhub\//\/libs\//g' ./doc/*.conf && \
sed -i 's/\/usr\/lib\/uhub\//\/libs\//g' ./doc/rules.txt && \
sed -i 's/\/etc\/uhub\//\/conf\//g' ./doc/*.conf && \
sed -i 's/\/etc\/uhub\//\/conf\//g' ./doc/rules.txt && \
echo 'Welcome to uHub' > ./doc/motd.txt

FROM alpine:latest
RUN apk update && apk upgrade && apk add --no-cache bash util-linux openssl-dev sqlite-dev
WORKDIR /app
COPY --from=builder /app/uhub .
COPY --from=builder /app/doc/plugins.conf /app/doc/uhub.conf /app/doc/users.conf /app/doc/rules.txt /app/doc/motd.txt /conf/
COPY --from=builder /app/*.so /libs/
ENTRYPOINT ["./uhub"]
CMD ["-c","/conf/uhub.conf"]
