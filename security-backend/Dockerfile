# ==============================================================================
# 🐳 PRODUCTION DOCKERFILE - AI SECURITY BACKEND
# ==============================================================================
#
# 🛡️ HOW THIS DOCKERFILE PREVENTS SERVER CRASHES & ENSURES HIGH AVAILABILITY:
#
# 1. 🪶 Minimal Alpine Base Image (node:20-alpine):
#    Reduces container size from >1GB to ~150MB. Minimizes memory footprint,
#    enabling dozens of container replicas to run concurrently without RAM exhaustion.
#
# 2. ⚡ Optimized Layer Caching & Clean Production Dependencies (npm ci):
#    Separately copies package files before application source code.
#    Installs strictly production dependencies, eliminating heavy dev dependencies.
#
# 3. 🔒 Non-Root Privilege Execution (USER node):
#    Runs the process under the unprivileged 'node' user instead of 'root',
#    preventing container breakout vulnerabilities and file system corruption.
#
# 4. 💓 Automated Healthcheck Monitoring:
#    Container runtime periodically polls '/api/health'. If an instance hangs or runs
#    out of memory (OOM), the orchestrator (Docker/K8s) automatically restarts it
#    and routes traffic away to healthy instances.
#
# 5. 🛑 Proper Signal Handling (dumb-init):
#    Ensures SIGTERM & SIGINT signals are forwarded to Node.js for clean shutdown
#    and closing of database connections without dropping active requests.
# ==============================================================================

# STAGE 1: Build & Dependency Resolution
FROM node:20-alpine AS dependencies

# Install dumb-init for proper PID 1 signal forwarding
RUN apk add --no-cache dumb-init

WORKDIR /usr/src/app

# Copy dependency manifests first to leverage Docker cache layers
COPY package*.json ./

# Install production dependencies only with strict clean install
RUN npm ci --only=production && npm cache clean --force

# ==============================================================================
# STAGE 2: Lightweight Production Runtime
# ==============================================================================
FROM node:20-alpine AS runner

WORKDIR /usr/src/app

# Set production environment flags (Optimizes Express performance & disables verbose debuggers)
ENV NODE_ENV=production
ENV PORT=5000

# Copy dumb-init from base
COPY --from=dependencies /usr/bin/dumb-init /usr/bin/dumb-init

# Copy node_modules from dependency stage
COPY --from=dependencies /usr/src/app/node_modules ./node_modules

# Copy application source code
COPY package*.json ./
COPY server.js ./

# Assign ownership of working directory to non-root user 'node'
RUN chown -R node:node /usr/src/app

# Switch to non-root user for security isolation
USER node

# Expose backend port
EXPOSE 5000

# Continuous Healthcheck Probe:
# Queries /api/health every 30s. If it fails 3 times, container status marks 'unhealthy'
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5000/api/health', (res) => { if (res.statusCode !== 200) process.exit(1); })" || exit 1

# Launch application via dumb-init for graceful shutdown & signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
