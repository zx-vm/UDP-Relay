FROM node:20-alpine

WORKDIR /app

COPY relay.js .

EXPOSE 8080

CMD ["node", "relay.js"]
