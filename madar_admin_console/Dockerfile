FROM node:20-bookworm-slim

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY tsconfig.json next.config.mjs tailwind.config.ts postcss.config.mjs ./
COPY src ./src

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV ADMIN_CONSOLE_PORT=5030

RUN npm run build

EXPOSE 5030

CMD ["npm", "run", "start"]
