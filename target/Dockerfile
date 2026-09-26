FROM gcc:13
WORKDIR /app
COPY server.c .
# disable protections so the overflow is a real SIGSEGV, not an abort
RUN gcc -O0 -U_FORTIFY_SOURCE -fno-stack-protector -o /usr/local/bin/target server.c
EXPOSE 9000
CMD ["/usr/local/bin/target"]
