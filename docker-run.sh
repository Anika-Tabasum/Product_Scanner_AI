#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if .env file exists, if not, create a sample one
if [ ! -f .env ]; then
    echo "Creating sample .env file. Please edit it with your actual values."
    cat > .env << EOF
# Database configuration
DATABASE_URL=postgres://postgres:postgres@db:5432/postgres
PGUSER=postgres
PGHOST=db
PGPASSWORD=postgres
PGDATABASE=postgres
PGPORT=5432

# App configuration
PORT=4060
SESSION_SECRET=change_this_to_a_random_string

# OpenAI API key - Replace with your actual API key
OPENAI_API_KEY=your_openai_api_key

# Email configuration - Optional
# EMAIL_HOST=smtp.example.com
# EMAIL_PORT=587
# EMAIL_USER=your_email_user
# EMAIL_PASS=your_email_password
# EMAIL_FROM=noreply@example.com
EOF
    echo ".env file created. Please edit it before continuing."
    exit 1
fi

# Build and start the containers
echo "Building and starting Docker containers..."
docker-compose up -d --build

# Wait for the database to be ready
echo "Waiting for the database to be ready..."
sleep 10

# Run migrations
echo "Running database migrations..."
docker-compose exec app npm run db:push

echo "Application is running at http://localhost:4060"