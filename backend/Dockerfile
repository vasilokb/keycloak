FROM node:16
WORKDIR /app
COPY package.json .
RUN npm install express @keycloak/keycloak-admin-client jsonwebtoken jwks-rsa cors
COPY . .
CMD ["node", "server.js"]