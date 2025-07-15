# 🐳 Self-Hosting FileKey as a Dockerized PWA
A big thank you to Wintech147 for putting this guide together!

---

## ✅ Prerequisites

- Docker already installed both on your build machine and on a docker host
- Nginx Proxy Manager is installed and accessible with LetsEncrypt configured
- You own a domain (e.g., `filekey.example.com`)
- You have DNS configured whether internally or externally that points to your proxy for traffic

---

This guide walks you through how to:

1. Clone the [FileKey](https://github.com/RockwellShah/filekey) repo
2. Add required PWA icons (optional)
3. Create a `Dockerfile` to serve it with Nginx
4. Build and push a Docker image to Docker Hub
5. Deploy it using Docker Compose

---

## 📁 Project Structure

```
filekey/
├── Dockerfile
├── docker-compose.yml
├── index.html
├── manifest.json
├── sw.js
└── icons/ (optional)
    ├── icon-192.png
    └── icon-512.png
```

---

## 🛠️ Step 1: Clone the GitHub Repository

```bash
git clone https://github.com/RockwellShah/filekey.git
cd filekey
```

---

## 🎨 Step 2: Add PWA Icons (Optional)

Since the original repo doesn't include actual icons, create your own:

1. Create icons in your favorit app. For PWAs they are best in .png.

2. Update `manifest.json` withe icon name and location based on the structure from above:

   ```json
   "icons": [
     {
       "src": "/icons/icon-192.png",
       "type": "image/png",
       "sizes": "192x192"
     },
     {
       "src": "/icons/icon-512.png",
       "type": "image/png",
       "sizes": "512x512"
     }
   ]
   ```
(Editor's note: there is now an SVG version of the FileKey icon in the repo.)

---

## 🐳 Step 3: Create Dockerfile

In the root of the cloned repo, create a file named `Dockerfile` and paste the below into it:

```dockerfile
FROM nginx:alpine

# Remove default Nginx page
RUN rm -rf /usr/share/nginx/html/*

# Copy static site into Nginx root
COPY . /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

---

## 🔨 Step 4: Build and Push Docker Image to Docker Hub

This assumes you have Docker installed on your local dev machine. This is not where you will be running the container just building the container image.

1. Build the image and don't leave out that trailing period: 
   ```bash
   docker build -t <your-dockerhub-username>/filekey:filekeyv1 .
   ```

Now you can choose to copy the image to your local docker host that you want the containers to run on and do docker run with the local image. I prefer to keep my images stored in Docker Hub to allow for easy pulls onto various hosts I run which is what I'm showing below:

2. Log in to Docker Hub:
   ```bash
   docker login
   ```

3. Push the image:
   ```bash
   docker push <your-dockerhub-username>/filekey:latest
   ```

> Replace `<your-dockerhub-username>` with your actual Docker Hub username. Use any tag you wish instead of 'latest'

---

## 🚀 Step 5: Deploy Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  filekey:
    image: <your-dockerhub-username>/filekey:filekeyv1
    container_name: filekey
    ports:
      - "8080:80"
    restart: unless-stopped
```

Choose any port that is open on your docker host in my case it was 8080 but this can be anything.

Deploy with:

```bash
docker compose up -d
```

Or paste into **Portainer > Stacks > Add Stack**.

---

## 🔐 Step 6: Add to NGINX Proxy Manager (or something similiar)

### ➕ Add New Proxy Host

- Go to your NGNIX Proxy Manager
- Go to **"Proxy Hosts"**
- Click **"Add Proxy Host"**

#### Fill in the following:

| Field              | Value                               |
|-------------------|-------------------------------------|
| **Domain Names**  | `filekey.example.com`               |
| **Scheme**        | `http`                              |
| **Forward Hostname / IP** | `your-docker-host-ip` or `localhost`if on the same host |
| **Forward Port**  | `8080` (or whatever FileKey is running on) |
| **Cache Assets**  | Optional          |
| **Block Common Exploits** | ✅ Recommended               |
| **Websockets Support** | ✅ Recommended                   |

---

### 🔒 Enable SSL (Let's Encrypt)

- Go to the **SSL** tab
- Check **“Enable SSL”**
- Check **“Force SSL”**
- Check **“HTTP/2 Support”**
- Check **“HSTS Enabled”**
- Choose **Choose your cert**

Click **Save**.

---

## 🌐 Step 7: Access the App

Once deployed and added to your proxy, visit:

```
https://filekey.example.com

http://<your-server-ip>:8080 (if not using a proxy)
```

---

## ✅ Summary

| Step                        | Description                               |
|-----------------------------|-------------------------------------------|
| Clone & customize           | Pull the repo, add icons, edit manifest and index.html   |
| Build image                 | `docker build -t yourname/filekey:tag .` |
| Push to Docker Hub          | `docker push yourname/filekey:tag`       |
| Deploy with Compose/Portainer | Map port 8080, restart unless stopped   |
| Add proxy host to NGINX Proxy Manager | docker host, port 8080, SSL   |
| PWA Ready                   | Installable with custom icon & manifest  |

---
