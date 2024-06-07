FROM nginx:alpine

EXPOSE 443

COPY default.conf /etc/nginx/conf.d/default.conf
COPY nginx.crt /etc/ssl/certs/nginx.crt
COPY --chmod=600 nginx.key /etc/ssl/certs/nginx.key