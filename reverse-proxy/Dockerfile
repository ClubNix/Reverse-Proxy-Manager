FROM alpine:latest
LABEL maintainer="Isnubi"

# Variables
ARG NGINX_DIR='/etc/nginx'
ARG NGINX_CONF_DIR='/etc/nginx/conf.d'
ARG NGINX_LOG_DIR='/var/log/nginx'
ARG NGINX_SSL_DIR='/etc/nginx/certs'

# Install nginx and other packages
RUN apk update && \
    apk add nginx pcre-tools openssl curl bash inotify-tools

# Clean up
RUN rm -rf /var/cache/apk/*

# Create directories
RUN mkdir -p /opt && \
    mkdir -p /run/nginx \
    mkdir -p $NGINX_SSL_DIR

# Backup default nginx configuration \
RUN mv $NGINX_DIR/nginx.conf $NGINX_DIR/nginx.conf.bak

COPY ./conf/nginx.conf $NGINX_DIR/nginx.conf
COPY ./conf/manager.sh /opt/manager.sh
COPY ./conf/watch_reload_nginx.sh /opt/scripts/watch_reload_nginx.sh
COPY ./conf/watch_conf_check.sh /opt/scripts/watch_conf_check.sh

# Configure nginx
RUN sed -i "s|\$NGINX_DIR|$NGINX_DIR|g" $NGINX_DIR/nginx.conf && \
    sed -i "s|\$NGINX_CONF_DIR|$NGINX_CONF_DIR|g" $NGINX_DIR/nginx.conf && \
    sed -i "s|\$NGINX_LOG_DIR|$NGINX_LOG_DIR|g" $NGINX_DIR/nginx.conf

# Get manager script
RUN sed -i "s|\$NGINX_CONF_DIR_REPLACE|$NGINX_CONF_DIR|g" /opt/manager.sh && \
    sed -i "s|\$NGINX_SSL_DIR_REPLACE|$NGINX_SSL_DIR|g" /opt/manager.sh && \
    sed -i "s|\$NGINX_LOG_DIR_REPLACE|$NGINX_LOG_DIR|g" /opt/manager.sh && \
    chmod +x /opt/manager.sh && \
    chmod +x /opt/scripts/watch_reload_nginx.sh && \
    chmod +x /opt/scripts/watch_conf_check.sh && \
    touch /opt/scripts/reload_nginx && \
    touch /opt/scripts/check_conf && \
    touch /opt/scripts/check_conf_status

# Set working directory
WORKDIR /opt

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s CMD curl --fail http://localhost/health.html || exit 1

# Expose ports
EXPOSE 80 443

# Run nginx
CMD ["/bin/bash", "-c", "/opt/scripts/watch_reload_nginx.sh & /opt/scripts/watch_conf_check.sh & nginx -g 'daemon off;'"]
