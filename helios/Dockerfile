FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.helios/bin:$PATH"

RUN curl -s https://raw.githubusercontent.com/a16z/helios/master/heliosup/install | bash && \
    /root/.helios/bin/heliosup

CMD /bin/bash -c "helios $STACK --rpc-bind-ip 0.0.0.0 --rpc-port $RPC_PORT --network $NETWORK --execution-rpc $EXECUTION_RPC --consensus-rpc $CONSENSUS_RPC"
