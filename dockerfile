# Use a Node.js base image
FROM node:18-alpine

# Set the working directory
WORKDIR /app

# Copy package.json and yarn.lock first to install dependencies
COPY package.json yarn.lock ./

# Install dependencies
RUN yarn install

# Copy the rest of the application files
COPY . .

# Run database migration
RUN npm run db:push

# Expose the port Vite runs on
EXPOSE 5000

# Start the Vite development server
CMD ["yarn", "run", "dev", "--host"]
