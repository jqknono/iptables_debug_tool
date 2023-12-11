# using alpine linux
# copy server binary to /bin/server
FROM alpine:3.7
WORKDIR /app
COPY dist/ /app
RUN chmod +x /app/server
RUN apk add libstdc++
RUN apk add libc6-compat
EXPOSE 55580/tcp
EXPOSE 55581/udp
CMD ["/app/server"]