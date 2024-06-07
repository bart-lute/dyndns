FROM troglobit/inadyn

COPY rootCA.crt /usr/share/ca-certificates/rootCA.crt
COPY ca-certificates.conf /etc/ca-certificates.conf
COPY inadyn.conf /etc/inadyn.conf
COPY --chmod=700 force-update.sh ./force-update.sh

RUN apk add curl && \
    /usr/sbin/update-ca-certificates