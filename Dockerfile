FROM golang:1.24 AS builder

COPY . .
RUN go build -o /giteeinterceptor cmd/main.go

FROM openeuler/openeuler:24.03
RUN dnf -y update --repo OS --repo update && \
    dnf in -y shadow --repo OS --repo update
RUN useradd -u 1001 -U -s /sbin/nologin -m interceptor
USER 1001:1001
COPY --chown=interceptor --from=builder /giteeinterceptor /home/interceptor/giteeinterceptor
RUN chmod 550 /home/interceptor/giteeinterceptor
EXPOSE 8080
ENTRYPOINT [ "/home/interceptor/giteeinterceptor" ]
