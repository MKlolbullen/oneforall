FROM node:22-alpine
WORKDIR /app/apps/web
COPY apps/web/package.json ./package.json
RUN npm install
COPY apps/web ./
EXPOSE 5173
CMD ["npm", "run", "dev"]
