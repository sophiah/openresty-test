FROM openresty/openresty:1.25.3.1-3-alpine-fat AS openresty_dev

USER root

ADD modules/ /opt/openresty/modules.src/
RUN mkdir -p /opt/openresty/modules /opt/openresty/cache
RUN for f in `ls /opt/openresty/modules.src/*.lua`; do \
    m="`basename ${f} | cut -d. -f1`"; \
    luajit -b /opt/openresty/modules.src/${m}.lua /opt/openresty/modules/${m}.luac; \
    done


FROM openresty/openresty:1.25.3.1-3-alpine AS openresty

RUN mkdir -p /opt/openresty/cache
COPY --from=openresty_dev /opt/openresty/modules /opt/openresty/modules

USER root
RUN adduser -g openresty openresty --disabled-password

RUN mkdir -p /var/run/openresty /usr/local/openresty/nginx/logs /opt/openresty && \
    chown -R openresty /var/run/openresty /usr/local/openresty/nginx/logs /opt/openresty

USER openresty

WORKDIR /home/openresty
