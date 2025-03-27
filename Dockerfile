# docker run --rm -it -v $(pwd)/OEM-KEYS:/src/OEM-KEYS genkeys:latest

FROM alpine:3.21.3

RUN apk add openssl coreutils

RUN mkdir /src/

# https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/appendix-openssl-configuration.html
COPY opensslroot.cfg /src/
# https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11/generate-local-insecure-root-key-and-certificates.html
COPY v3.ext /src/
COPY v3_attest.ext /src/

# script to run the 
COPY genkeys.sh /src/
RUN chmod 755 /src/genkeys.sh

WORKDIR /src/
ENTRYPOINT ["/src/genkeys.sh"]
