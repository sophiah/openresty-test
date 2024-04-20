FROM openresty/openresty:1.25.3.1-3-alpine-fat AS openresty_dev

USER root

# RUN set -e; \
#     apt-get update; \
#     apt-get install -y \
#         zip wget vim procps net-tools

WORKDIR /home/openresty
ADD modules/ /home/openresty/modules.src/
RUN mkdir -p /home/openresty/modules
RUN for f in `ls /home/openresty/modules.src/*.lua`; do \
    m="`basename ${f} | cut -d. -f1`"; \
    luajit -b /home/openresty/modules.src/${m}.lua /home/openresty/modules/${m}.luac; \
    done

RUN adduser -g openresty openresty --disabled-password

USER openresty


FROM openresty_dev AS openresty

USER root
# RUN apt-get -y purge --auto-remove \
#     zip wget vim procps net-tools 

USER openresty

CMD ["/usr/bin/openresty", "-g", "daemon off;"]
