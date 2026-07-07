# Shuffle `docker-compose.yml` — required edits (single-box lab)   [SANITIZED]

The full `~/Shuffle/docker-compose.yml` lives on the Ubuntu host and is not reproduced here
(it's the upstream file from `git clone https://github.com/Shuffle/Shuffle`). Only the changes
made for this lab are documented below — apply these to a fresh clone.

> Replace `<MANAGER_IP>` with your host IP where relevant. No secrets should be committed to this
> file; Shuffle's auth/org values live in the app and in the running containers, not here.

## 1. Remap Shuffle's OpenSearch port (avoid clash with Wazuh indexer on 9200)

The `opensearch` service publishes `9200:9200`, which collides with the Wazuh indexer. Change the
**host** side to 9201:

```yaml
# opensearch service — ports:
    ports:
      - 9201:9200        # was: 9200:9200
```

Or apply directly:
```bash
sed -i 's/- 9200:9200/- 9201:9200/' ~/Shuffle/docker-compose.yml
```

## 2. Cap the OpenSearch heap (8 GB host)

Under the `opensearch` service `environment:` list, pin the JVM heap low so it doesn't fight the
Wazuh indexer (both values must be equal):

```yaml
# opensearch service — environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
```

## 3. Disable Swarm-based workers (run workers as plain containers)

On a single node, Swarm worker deployment breaks (stale services + vxlan overlay errors). Under the
`orborus` service `environment:`, set the swarm config to empty (default is `run`):

```yaml
# orborus service — environment:
      - SHUFFLE_SWARM_CONFIG=        # was: SHUFFLE_SWARM_CONFIG=run
```

## Apply changes

After editing, recreate the affected containers (a daemon restart alone does NOT re-read the
compose file):

```bash
cd ~/Shuffle
docker compose up -d --force-recreate opensearch orborus
docker compose ps
```

## Host prerequisites (not in the compose file)

```bash
# persistent kernel setting for OpenSearch
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-shuffle.conf
sudo sysctl -p /etc/sysctl.d/99-shuffle.conf

# 4 GB swapfile (required on 8 GB box; do NOT run `swapoff -a`)
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# data dir ownership
sudo chown -R 1000:1000 ~/Shuffle/shuffle-database
```
