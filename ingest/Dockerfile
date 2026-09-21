FROM node:20-alpine

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy the rest of the source.
COPY . .

ENV NODE_ENV=production \
    DATASET_DIR=/app/dataset

CMD ["node", "index.js"]
