# Deployment

This fork adds a CI/CD pipeline to build and deploy a self-hosted instance of Filekey.

## CI/CD

### Push to `main`

1. Tag the current `latest` image as `previous` (for rollback)
2. Build and push the new `latest` image to Docker Hub
3. Trigger deployment via n8n webhook
4. Verify in production that `/version.txt` matches the expected SHA
5. **Automatic rollback** if the production check fails: `previous` is re-tagged as `latest` and redeployed

### Required secrets

| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN`    | Docker Hub access token |
| `N8N_WEBHOOK_ID`     | n8n webhook ID triggering the redeployment |