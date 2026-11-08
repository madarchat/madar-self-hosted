FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates ffmpeg \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY bin ./bin

RUN mkdir -p /app/uploads

ENV NODE_ENV=production
EXPOSE 5025
EXPOSE 3478/udp

CMD ["node", "src/index.js"]
