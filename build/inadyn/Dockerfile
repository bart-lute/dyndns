FROM troglobit/inadyn

COPY rootCA.crt /usr/share/ca-certificates/rootCA.crt
COPY inadyn.conf /etc/inadyn.conf
COPY --chmod=700 force-update.sh ./force-update.sh

RUN apk add curl bash && \
    echo "rootCA.crt" >> /etc/ca-certificates.conf && \
    /usr/sbin/update-ca-certificates