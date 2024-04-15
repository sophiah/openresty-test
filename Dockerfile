FROM openresty/openresty:1.25.3.1-0-bookworm-fat AS openresty_dev

USER root

RUN set -e; \
    apt-get update; \
    apt-get install -y \
        zip wget vim procps net-tools

WORKDIR /home/openresty
RUN useradd -ms /bin/bash openresty && mkdir -p /home/openresty

USER openresty


FROM openresty_dev AS openresty

USER root
RUN apt-get -y purge --auto-remove \
    zip wget vim procps net-tools

USER openresty

CMD ["/usr/bin/openresty", "-g", "daemon off;"]
