# Troubleshooting

If API returns connection refused, check:

```bash
docker compose ps -a
docker compose logs --tail=120 api
```

If target validation fails, inspect URL policy decisions from `/api/targets/{target_id}/validate`.

