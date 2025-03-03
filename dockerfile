# Stage 1: Build Client
FROM node:18-alpine AS client

WORKDIR /app/client
COPY client/package*.json ./
RUN npm install
COPY client/ .
RUN npm run build

# Stage 2: Build Server
FROM node:18-alpine  # <- Removed "AS server" to make this the final image

WORKDIR /app/server
COPY server/package*.json ./
RUN npm install
COPY server/ .
COPY --from=client /app/client/dist ./public  # Copy built frontend

EXPOSE 3000

CMD ["npm", "run", "start"]  # Ensure it runs production mode
