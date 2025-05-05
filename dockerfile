# --- Build Stage ---
FROM node:18-alpine AS builder
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY . .
RUN yarn build

# --- Production Stage ---
FROM node:18-alpine AS production
WORKDIR /app
COPY --from=builder /app /app
RUN yarn install --production --frozen-lockfile && yarn cache clean
RUN npm run db:push

# Railway sets the PORT env variable
ENV NODE_ENV=production
EXPOSE 8080

CMD ["yarn", "start"]
