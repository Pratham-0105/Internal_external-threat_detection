# Stage 1: Build Vite React Application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package descriptors
COPY package*.json ./

# Install dependencies using legacy-peer-deps for React 19 compatibility
RUN npm install --legacy-peer-deps

# Copy source files
COPY . .

# Build production bundle
RUN npm run build

# Stage 2: Production Nginx Server
FROM nginx:alpine

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build artifacts from builder stage
COPY --from=builder /app/build /usr/share/nginx/html

# Expose Frontend Port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --spider -q http://localhost:3000/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
