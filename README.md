# gostore

**Servidor de object storage compatível com Amazon S3, escrito do zero em Go.**

Um binário. Sem banco de dados. Sem dependência externa. Fala o protocolo S3 de
verdade — SigV4, multipart, range, presigned, requests condicionais — então
qualquer SDK da AWS, `aws-cli`, `mc`, `rclone`, `s3fs` ou Cyberduck conecta só
trocando o endpoint. Traz erasure coding Reed-Solomon com proteção contra
bitrot, IAM no estilo AWS, versionamento, Object Lock (WORM), criptografia em
repouso, console web embutido — e uma camada de recursos que o MinIO community
e o próprio S3 não entregam: deduplicação por conteúdo, compressão transparente,
tiering pra storage frio, snapshots com restauração ponto-no-tempo, backup
automático agendado, TTL por objeto, cache de objeto quente em RAM, pipeline de
imagem (resize/crop), hospedagem de site estático e log de auditoria à prova de
adulteração.

Licença **Apache 2.0** — uso comercial livre, sem copyleft de rede (ao
contrário do AGPL do MinIO).

```bash
docker run -d -p 9000:9000 -v gostore-data:/data \
  -e GOSTORE_ROOT_USER=admin -e GOSTORE_ROOT_PASSWORD=troque-esta-senha \
  ghcr.io/fdsriopreto-code/gostore-s3:latest

# console:  http://localhost:9000/gostore/console/
# saúde:    http://localhost:9000/gostore/health/selftest
```

---

## Índice

- [Por que gostore](#por-que-gostore)
- [Screenshots](#screenshots)
- [Início rápido](#início-rápido)
- [Usar como backend da sua aplicação](#usar-como-backend-da-sua-aplicação)
- [Compatibilidade S3](#compatibilidade-s3)
- [Diferenciais](#diferenciais)
- [Erasure coding](#erasure-coding)
- [Arquitetura](#arquitetura)
- [Configuração (variáveis de ambiente)](#configuração-variáveis-de-ambiente)
- [Deploy](#deploy)
- [CLI embutida](#cli-embutida)
- [Teste de carga](#teste-de-carga)
- [Integrações](#integrações)
- [Segurança](#segurança)
- [Estado do projeto](#estado-do-projeto)
- [Testes](#testes)
- [Licença](#licença)

---

## Por que gostore

| | |
|---|---|
| **Um binário, zero infra** | Sem Postgres, sem etcd, sem Redis. Objetos, metadados, IAM e configuração de bucket vivem no volume, no estilo do MinIO. Copiar o binário e apontar pra uma pasta já é um servidor S3. |
| **Protocolo S3 real** | SigV4 (header, presigned, POST-form, `aws-chunked` streaming com cadeia de assinatura), path-style e virtual-host, erros XML no formato S3, `ListObjectsV2` com `CommonPrefixes`, multipart completo, `Range`/206, `If-Match`/`If-None-Match`/`If-*-Since` em GET **e** PUT. O código do seu app não muda entre AWS e gostore. |
| **Durabilidade de verdade** | Erasure coding Reed-Solomon (sobrevive à perda de metade dos discos), bitrot HighwayHash-256 por stripe intercalado no shard, `xl.meta` replicado com resolução por maioria, healing sob demanda + fila MRF pra escritas parciais + deep scrub semanal. Escrita atômica `write-tmp + fsync + rename`. |
| **Bateria inclusa** | Console web (SPA embutida, sem build), CLI cliente no mesmo binário, métricas Prometheus, log de atividade ao vivo, healthchecks e um selftest que faz um round-trip completo e responde JSON. |
| **Vai além do S3** | Dedup por conteúdo, compressão zstd em repouso, tiering pra S3 frio, snapshots de bucket, backup automático, TTL por objeto, cache em RAM, thumbnails/resize on-the-fly, site estático, append em objeto, auditoria hash-encadeada, KMS externo via Vault. |
| **Apache 2.0** | Rode, modifique e embarque em produto fechado sem obrigação de abrir seu código. |

---

## Screenshots

O console web é servido pelo próprio binário em `/gostore/console/` — sem build,
sem processo separado.

![Dashboard](docs/screenshots/dashboard.png)
<sub>**Dashboard** — endpoint, região, modo (single-disk ou erasure), capacidade.</sub>

![Buckets](docs/screenshots/buckets.png)
<sub>**Buckets** — criar, navegar, uso por pasta, drag & drop de upload.</sub>

![Monitoring](docs/screenshots/monitoring.png)
<sub>**Data health** — deep scrub, falhas de integridade, read-repairs na fila,
heal ok/erro, read-only, verificação da cadeia de auditoria.</sub>

<details>
<summary>Mais telas</summary>

![Access Keys](docs/screenshots/access-keys.png)
<sub>**Access Keys** — usuários e service accounts, policy, rotação de secret.</sub>

![Documentation](docs/screenshots/docs.png)
<sub>**Documentation** — ~15 páginas embutidas: conectar SDK, presigned, IAM,
versionamento, Object Lock, lifecycle, replicação, criptografia, admin API,
cluster.</sub>

</details>

---

## Início rápido

### Docker (single-disk)

```bash
docker run -d --name gostore -p 9000:9000 \
  -v gostore-data:/data \
  -e GOSTORE_ROOT_USER=admin \
  -e GOSTORE_ROOT_PASSWORD=uma-senha-forte-min-8 \
  ghcr.io/fdsriopreto-code/gostore-s3:latest

curl -s localhost:9000/gostore/health/selftest    # {"ok":true,"steps":[...]}
```

Console: **http://localhost:9000/gostore/console/** (login com as credenciais acima).

### Binário local

```bash
make build                       # -> dist/gostore
GOSTORE_ROOT_USER=admin GOSTORE_ROOT_PASSWORD=uma-senha-forte-min-8 \
  dist/gostore server ./data
```

### Erasure coding (durabilidade)

O modo é escolhido pela quantidade de volumes passada ao `server`:

```bash
# 4 discos = 2 dados + 2 paridade -> aguenta perder 2 discos sem perder dado
gostore server /data/d1 /data/d2 /data/d3 /data/d4
gostore server /data/d{1...4}          # sintaxe de ellipsis
```

Os N volumes podem ser pastas do mesmo disco físico (protege contra bitrot e
reconstrói, mas não dá redundância física) ou — ideal — N discos/mounts
separados.

### Primeiro objeto (aws-cli)

```bash
aws configure set aws_access_key_id admin
aws configure set aws_secret_access_key uma-senha-forte-min-8
aws configure set default.region us-east-1
aws configure set default.s3.addressing_style path

aws --endpoint-url http://localhost:9000 s3 mb s3://meu-bucket
echo "olá gostore" > ola.txt
aws --endpoint-url http://localhost:9000 s3 cp ola.txt s3://meu-bucket/
aws --endpoint-url http://localhost:9000 s3 ls s3://meu-bucket
```

---

## Usar como backend da sua aplicação

gostore é feito pra ser o storage do seu serviço: avatares, uploads de usuário,
anexos, vídeos, dumps de backup. O SDK oficial da AWS conecta trocando só
`endpoint` e `forcePathStyle`.

> **"Pasta" em S3 não existe.** A key `avatars/user_123/foto.webp` é um nome
> plano — a `/` é convenção. Você não cria pasta: faz `PutObject` com a key que
> quiser e ela "aparece". Pra navegar como pasta, `ListObjectsV2` com
> `Delimiter: "/"` devolve os prefixos (`CommonPrefixes`). O console mostra
> isso como árvore de pastas.

### Node.js — `@aws-sdk/client-s3`

```js
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const s3 = new S3Client({
  endpoint: process.env.S3_ENDPOINT,          // https://storage.seu-dominio.com
  region: "us-east-1",
  forcePathStyle: true,                        // obrigatório
  credentials: {
    accessKeyId: process.env.S3_KEY,
    secretAccessKey: process.env.S3_SECRET,
  },
});

// avatar — a "pasta" avatars/<uid>/ nasce sozinha
await s3.send(new PutObjectCommand({
  Bucket: "app-prod",
  Key: `avatars/${userId}/original.webp`,
  Body: buffer,
  ContentType: "image/webp",
}));

// vídeo grande — multipart automático, cada parte com retry
await new Upload({
  client: s3,
  params: {
    Bucket: "app-prod",
    Key: `videos/${userId}/${videoId}.mp4`,
    Body: readableStream,
    ContentType: "video/mp4",
  },
}).done();

// link temporário pra servir um arquivo privado sem expor credencial
const url = await getSignedUrl(
  s3,
  new GetObjectCommand({ Bucket: "app-prod", Key: `avatars/${userId}/original.webp` }),
  { expiresIn: 3600 },
);
```

Miniatura on-the-fly (sem processar imagem no seu back-end):

```
GET /app-prod/avatars/123/original.webp?w=128&h=128&fit=cover&format=jpeg
```

### Python — `boto3`

```python
import boto3
s3 = boto3.client(
    "s3",
    endpoint_url="https://storage.seu-dominio.com",
    aws_access_key_id="...", aws_secret_access_key="...",
    region_name="us-east-1",
    config=boto3.session.Config(s3={"addressing_style": "path"}),
)
s3.upload_fileobj(f, "app-prod", f"users/{uid}/documento.pdf")
```

Outros: `aws-sdk-go-v2`, Laravel/Flysystem (`driver: s3` + `endpoint`), Rails
ActiveStorage (`service: S3` + `endpoint`), Django `django-storages`,
`rclone`, `s3fs` — tudo funciona igual como se fosse a AWS.

### Backup de outro sistema sem SDK (ingest keys)

Pra quando um serviço só precisa **empurrar** arquivo pra dentro (um dump do
Postgres, por exemplo) sem carregar um SDK nem assinar SigV4:

```bash
# no console: bucket Settings -> Ingest keys -> Generate (escopo de prefixo)
pg_dump "$DATABASE_URL" | gzip | \
  curl -T - -H "Authorization: Bearer gik_xxxxxxxx" \
  https://storage.seu-dominio.com/gostore/ingest/backups/pg/
```

A chave só escreve, só no prefixo dela, sem expiração. Terminar a key em `/`
faz o gostore datar o nome do arquivo automaticamente.

---

## Compatibilidade S3

Path-style e virtual-host style. Região default `us-east-1`.

| Cliente | Como apontar |
|---|---|
| **AWS SDK** (JS, Python, Go, Java, PHP, Ruby, .NET) | `endpoint` + path-style / `forcePathStyle` |
| **aws-cli** | `aws --endpoint-url https://... s3 ...` |
| **MinIO `mc`** | `mc alias set gs https://... KEY SECRET` |
| **rclone** | `type = s3`, `provider = Other`, `endpoint = https://...` |
| **s3fs / goofys** | monta um bucket como filesystem |
| **Cyberduck / Transmit** | perfil S3 com endpoint custom |

### Operações implementadas

**Service** — `ListBuckets`.

**Bucket** — `CreateBucket` (com `x-amz-bucket-object-lock-enabled`),
`DeleteBucket`, `HeadBucket`, `GetBucketLocation`, `Get/Put/DeleteBucketPolicy`,
`Get/Put/DeleteBucketTagging`, `Get/Put/DeleteBucketCors`,
`Get/PutBucketNotification`, `Get/PutBucketVersioning`,
`Get/PutObjectLockConfiguration`, `Get/PutBucketReplication`,
`Get/PutBucketLifecycleConfiguration`, `Get/PutBucketWebsite`, `?quota`,
`?compression`, `ListObjects` (v1), `ListObjectsV2`, `ListObjectVersions`,
`ListMultipartUploads`, `DeleteObjects` (lote, paralelo).

**Object** — `PutObject` (+ `aws-chunked` streaming, `x-amz-checksum-*`,
`If-Match`/`If-None-Match`, `x-amz-write-offset-bytes` pra append),
`GetObject` (Range + condicionais + `?partNumber`), `HeadObject`,
`DeleteObject`, `CopyObject` / `UploadPartCopy`,
`Get/Put/DeleteObjectTagging`, `Get/PutObjectRetention`,
`Get/PutObjectLegalHold`, `?versionId`. **Multipart** completo
(`Create`/`UploadPart`/`Complete`/`Abort`/`ListParts`). **POST Object**
(upload por formulário do browser, com policy assinada).

---

## Diferenciais

Recursos que o MinIO community edition e/ou o S3 não entregam. Tudo opcional,
desligado por default, ativável por bucket ou por env var.

| Recurso | O que faz | Como liga |
|---|---|---|
| **Dedup por conteúdo** | Objetos byte-idênticos compartilham os mesmos shards no disco (`.gostore.sys/cas/<sha256>/`). Referência por hash no `xl.meta`, garbage-collect mark-and-sweep no deep scrub. | `GOSTORE_DEDUP=1` (erasure) |
| **Compressão zstd em repouso** | Comprime antes de codificar; pula tipos já comprimidos e arquivos < 512 B. ETag continua sendo o md5 do plaintext. | bucket Settings → *Compression* |
| **Tiering pra storage frio** | Regra de lifecycle `Transition` move o objeto pra um backend S3 remoto (Backblaze B2, Cloudflare R2, Wasabi, outro gostore); leitura e range servem transparente do remoto. | `GOSTORE_TIER_<NOME>=s3,endpoint,região,bucket,key,secret` + regra `?lifecycle` |
| **Snapshots + restauração ponto-no-tempo** | Congela a versão de cada objeto do bucket num manifesto; restaura o bucket inteiro pra aquele instante de forma **não destrutiva** (cada rollback é uma versão nova). | `POST /gostore/admin/v1/snapshot?bucket=X` (precisa de versionamento) |
| **Backup automático agendado** | Espelha todo objeto pra um tier remoto numa cadência fixa. Incremental (pula o que o destino já tem no mesmo tamanho), single-flight, sobrevive a restart. | console *Monitoring → Automatic backup* |
| **Ingest keys** | Upload write-only com um header (`Authorization: Bearer gik_…`), sem SigV4, com escopo de prefixo. Pra qualquer back-end empurrar backup pra dentro. | bucket Settings → *Ingest keys* |
| **TTL por objeto** | `X-Gostore-Expires: <RFC3339>` ou `X-Gostore-Expire-After: 72h` / `7d` / `2w` no PUT → o objeto some sozinho (na leitura e no scanner). | header no PUT |
| **Cache de objeto quente** | LRU em RAM com orçamento de bytes; GET/HEAD de objeto pequeno servido da memória (`x-gostore-cache: HIT`), coerente com escrita/delete. | `GOSTORE_OBJ_CACHE=128MiB` |
| **Pipeline de imagem** | `?w=&h=&fit=contain\|cover&format=jpeg\|png&q=` — resize com média de área, nunca faz upscale, resultado cacheado por transformação. | query string no GET |
| **Hospedagem de site estático** | `?website` com index/error document; GET sem query serve `index.html` de `/` e de `dir/`. | `PutBucketWebsite` |
| **Append em objeto** | `PutObject` + `x-amz-write-offset-bytes: N` anexa se `N == tamanho atual`, senão `409`. Concorrência-segura sem lock novo. | header no PUT |
| **Log de auditoria à prova de adulteração** | Toda mutação bem-sucedida vira uma entrada hash-encadeada (`Hash = sha256(prevHash‖entry)`), também gravada em JSONL diário. Qualquer edição quebra a cadeia. | sempre ligado; `GET /gostore/admin/v1/audit/verify` |
| **Checksums adicionais** | `x-amz-checksum-{crc32,crc32c,sha1,sha256}` verificado em streaming no PUT (mismatch → 400, nada é gravado), devolvido no GET/HEAD. | header no PUT |
| **KMS externo (Vault)** | `GOSTORE_KMS_VAULT_ADDR` + `_TOKEN` → o wrap/unwrap da DEK vai pro Vault Transit; a master key nunca fica no processo. | env var |
| **Read-only mode** | Manual ou automático quando o quorum de escrita fica impossível — rejeita toda escrita com `503` e continua servindo leitura. | `POST /gostore/admin/v1/readonly` |
| **Rate limit + admission control** | Token bucket por access key; teto global de bytes de corpo em voo → `503 SlowDown` + `Retry-After` em vez de estourar memória. | `GOSTORE_RATE_LIMIT`, auto |
| **Uso por pasta** | O scanner credita o tamanho de cada objeto a cada prefixo ancestral; o console mostra `tamanho · nº de objetos` por pasta. | `GET /gostore/admin/v1/du?bucket=X&prefix=P/` |

---

## Erasure coding

Cada parte de um objeto é quebrada em *stripes* de `blockSize` (1 MiB). Cada
stripe vira `N/2` shards de dados + `N/2` shards de paridade (Reed-Solomon), um
shard por disco. O objeto sobrevive à perda de até `N/2` discos.

- **`xl.meta`** (JSON) é escrito **idêntico em todos os discos**; na leitura a
  versão vencedora é escolhida por maioria (`contentHash`), com desempate por
  `Revision` (contador monotônico por objeto).
- **Objetos pequenos** (até `GOSTORE_INLINE_MAX`, default 128 KiB) vão *dentro*
  do `xl.meta` (campo `inline`) — uma operação de arquivo por disco em vez de
  um shard-file extra.
- **Bitrot**: HighwayHash-256 por bloco de stripe, gravado **intercalado no
  próprio shard-file** (`[hash|bloco][hash|bloco]…`), então o `xl.meta` tem
  tamanho constante. Na leitura, um bloco cujo hash não bate é descartado e o
  Reed-Solomon reconstrói a partir dos bons — inclusive em leitura por range.
- **Verificação ponta-a-ponta**: num GET de objeto inteiro os bytes montados
  são re-hasheados e comparados ao ETag — pega bug de montagem/decode que o
  bitrot por bloco não pega (`gostore_integrity_failures_total`).
- **Healing**: escritas que atingem quorum mas não todos os discos entram numa
  fila **MRF** persistente e são re-healadas em background; a leitura que
  reconstrói em torno de um shard ruim enfileira o objeto (`read-repair`); o
  **deep scrub** (`GOSTORE_SCRUB_INTERVAL`, default 168h) verifica e repara
  todo objeto; um disco novo/substituído é detectado no boot e repovoado.
- **Quorum**: leitura = `N/2` discos; escrita = `N/2 + 1`.
- **Multipart**: cada parte é um blob erasure-coded próprio em
  `.gostore.sys/multipart/`; no `Complete` as partes são decodificadas em
  streaming e reescritas como as partes do objeto final.

**Cluster multi-nó** (`internal/cluster`): endpoints
`http(s)://host:port/data/d{1...4}` de todos os nós formam **um** erasure set;
disco remoto sobre um transporte de grid multiplexado (uma conexão TCP por par
de nós, handshake `Upgrade: gostore-grid`, com fallback HTTP); lock por quorum
estilo dsync (N/2+1 concedem, TTL + refresh, fencing por token monotônico);
circuit breaker por peer. Membership é estático. IAM e config de bucket são
replicados pela camada de objetos e recarregados a cada 30 s.

Layout no disco (modo erasure):

```
<disco>/<bucket>/<key>/xl.meta          cópia completa dos metadados
<disco>/<bucket>/<key>/part.00001       shard deste disco pra parte 1
<disco>/.gostore.sys/format.json        identidade do disco (set + índice)
<disco>/.gostore.sys/cas/<sha256>/      blobs compartilhados (dedup)
<disco>/.gostore.sys/tmp/               staging do rename atômico
```

---

## Arquitetura

**Sem banco de dados.** Objetos, `xl.meta`, IAM, config de bucket, manifests de
snapshot, fila MRF, log de auditoria — tudo vive nos volumes, sob
`.gostore.sys/`. Os únicos externos opcionais: KMS (Vault) e alvos de evento
(webhook).

```
cmd/gostore/        entrypoint `server`, bootstrap, graceful shutdown,
                    applyCPULimit (GOMAXPROCS = cota do cgroup), memguard
internal/
  config/           flags + env GOSTORE_*, grupos de volume, validação
  auth/             AWS SigV4 (header / presigned / aws-chunked) — primitivas
  api/              camada HTTP S3 + admin: router (path + vhost), ~30 erros
                    S3→XML, authenticate + authorize (IAM + bucket policy),
                    handlers de service/bucket/object/multipart/tagging/policy/
                    cors/notification/versioning/object-lock/replication/
                    lifecycle/website/snapshot/backup/ingest, STS, admin API,
                    /gostore/console (SPA), /gostore/health/*, /gostore/metrics
  object/           object.Layer (abstração central) + types + errors
  object/fs/        backend single-disk: CRUD, multipart, range, versionamento
                    real, Object Lock (WORM), SSE-S3, tagging
  storage/          StorageAPI + LocalDisk (uma pasta = um "disco")
  erasure/          Reed-Solomon (klauspost), Set (N discos) + Pool (N sets),
                    xl.meta replicado, bitrot por stripe, quorum, heal, MRF,
                    versionamento + Object Lock por vlog, dedup, compressão,
                    tiering, decommission + rebalance de set online
  cluster/          RemoteDisk sobre grid multiplexado, RPCServer, lock por
                    quorum (dsync-lite), circuit breaker, parse de topologia
  nslock/           striped RWMutex 4096-way (lock de namespace)
  iam/              usuários / service accounts / STS + engine de policy AWS
  kms/  sse/        master key local ou Vault Transit + AES-256-GCM em chunks
  bucketcfg/        config por bucket — JSON replicado nos volumes
  configstore/      Backend (Read/Write/Delete/ListConfig) — fs e erasure
  event/            barramento de notificação → webhooks
  replication/      cópia async pra bucket local ou endpoint S3 remoto
  scanner/          passada única de background: ILM, uso por bucket/pasta,
                    heal sample, deep scrub
  remotes3/         cliente S3 SigV4 streaming (tiering, backup, replicação)
  metrics/          exposição Prometheus sem dependência
  gostorecli/       o cliente `gostore` (ls/cp/rm/mb/rb/cat/stat/admin/bench)
  console/          SPA embutida (go:embed), servida pela própria API
```

Escrita é atômica: `write-tmp → fsync → rename`, com fsync do diretório pai no
commit (POSIX) — configurável via `GOSTORE_FSYNC=0`.

---

## Configuração (variáveis de ambiente)

### Essenciais

| Var | Default | Descrição |
|---|---|---|
| `GOSTORE_ROOT_USER` | `gostoreadmin` | access key raiz |
| `GOSTORE_ROOT_PASSWORD` | — | secret key raiz (**mín. 8 chars**) |
| `GOSTORE_REGION` | `us-east-1` | região reportada nas respostas |
| `GOSTORE_ADDRESS` | `:9000` | endereço da API S3 |
| `GOSTORE_CONSOLE_ADDRESS` | `:9001` | endereço do console (opcional; o console também é servido na API em `/gostore/console/`) |
| `GOSTORE_DOMAIN` | — | habilita endereçamento virtual-host (`bucket.dominio`) |

### TLS embutido (Let's Encrypt, sem proxy)

| Var | Descrição |
|---|---|
| `GOSTORE_TLS_DOMAIN` | `s3.exemplo.com[,outro.com]` → pega e renova o cert sozinho |
| `GOSTORE_TLS_EMAIL` | contato ACME |
| `GOSTORE_TLS_HTTP_ADDR` | porta do desafio HTTP-01 (default `:80`) |

Cert em `<volume>/.gostore.sys/acme/`. Exponha 80 e 443.

### Runtime / recursos

| Var | Default | Descrição |
|---|---|---|
| `GOMEMLIMIT` / `GOSTORE_MEM_LIMIT` | cgroup × 90% | limite soft de memória (aceita `256MiB`, `1g`) |
| `GOSTORE_MAXPROCS` | `ceil(cota CPU)+1` | override do GOMAXPROCS (auto-derivado do cgroup) |
| `GOSTORE_MAX_INFLIGHT_BYTES` | `512MiB` | teto de corpo de request em voo → `503 SlowDown` |
| `GOSTORE_RATE_LIMIT` / `_BURST` | — | token bucket por access key |
| `GOSTORE_IDLE_TIMEOUT` | `90s` | mata upload travado que prende lock |
| `GOSTORE_TRUSTED_PROXIES` | loopback + ranges privados | CIDRs/IPs cujo `X-Forwarded-For` é confiável (fonte do IP p/ `IpAddress` nas policies e rate-limit); fora disso o header é ignorado (anti-spoof) |
| `GOSTORE_COPY_SOURCE_AUTHZ` | `enforce` | `enforce`/`warn`/`off` — exige (ou só avisa) permissão de leitura na origem de `CopyObject` |

### Storage / erasure

| Var | Default | Descrição |
|---|---|---|
| `GOSTORE_INLINE_MAX` | `131072` | objeto até N bytes fica dentro do `xl.meta` (`0` desliga) |
| `GOSTORE_MRF_INTERVAL` | `5m` | cadência do auto-heal de escrita parcial |
| `GOSTORE_SCRUB_INTERVAL` | `168h` | cadência do deep scrub (`0` desliga) |
| `GOSTORE_HEAL_CONCURRENCY` / `_SLEEP` | `2` | throttle do healing |
| `GOSTORE_LIST_CACHE_TTL` | `15s` | cache de listagem por bucket (`0` desliga) |
| `GOSTORE_DISK_OP_TIMEOUT` | `30s` | deadline por operação de disco |
| `GOSTORE_SCAN_INTERVAL` | `1h` | cadência do scanner (ILM + uso + heal sample) |
| `GOSTORE_FSYNC` | `1` | fsync de diretório no commit (`0` troca durabilidade por throughput) |

### Recursos opcionais

| Var | Descrição |
|---|---|
| `GOSTORE_DEDUP=1` | deduplicação por conteúdo (erasure) |
| `GOSTORE_COMPRESS_DISABLE=1` | desliga a compressão zstd globalmente |
| `GOSTORE_TIER_<NOME>` | `s3,endpoint,região,bucket,key,secret[,prefix]` — destino de tiering/backup |
| `GOSTORE_KMS_VAULT_ADDR` / `_TOKEN` / `_KEY` | KMS externo via Vault Transit |
| `GOSTORE_KMS_MASTER_KEY` | master key SSE-S3 local (base64 de 32 bytes; senão é gerada) |
| `GOSTORE_OBJ_CACHE` / `_MAX_OBJ` / `_TTL` | cache de objeto quente em RAM |
| `GOSTORE_METRICS_TOKEN` | exige `Authorization: Bearer` em `/gostore/metrics` |
| `GOSTORE_NO_CONTENT_TYPE_SNIFF=1` | não adivinha Content-Type pela extensão |
| `GOSTORE_ALLOW_ANONYMOUS=1` | aceita request sem assinatura (**só debug**) |
| `GOSTORE_DISABLE_SELFTEST=1` | desliga `/gostore/health/selftest` |
| `GOSTORE_CLUSTER_SELF` / `GOSTORE_CLUSTER_SECRET` | modo cluster multi-nó |
| `GOSTORE_LOG_LEVEL` / `GOSTORE_LOG_JSON=1` | logging |

---

## Deploy

### Docker Compose

```bash
docker compose up -d --build      # edite as credenciais antes
# S3 API  -> http://<host>:9000
# Console -> http://<host>:9001  (ou :9000/gostore/console/)
```

A imagem roda como **root** (igual à imagem oficial do MinIO) pra escrever em
qualquer mount que a plataforma fornecer. Pra host multi-tenant, use `--user` e
pré-`chown` o volume.

### EasyPanel / Coolify / Dokploy (PaaS sem shell)

1. **App type:** Dockerfile, apontando pro repo, branch `main`.
2. **Porta exposta:** `9000`.
3. **Env vars:** `GOSTORE_ROOT_USER`, `GOSTORE_ROOT_PASSWORD` (≥ 8), `GOSTORE_REGION`.
4. **Volume persistente em `/data`.**
   ⚠️ **Sem esse volume, TUDO some a cada redeploy** — buckets, objetos e access
   keys. Não há banco externo. Se o log mostrar
   `data volume was EMPTY at startup` (e o Dashboard avisar), o mount não está
   persistindo. Confira em `GET /gostore/health/persistence`.
5. Deploy. Domínio do painel → serviço, porta `9000`.

### Cluster multi-nó

```bash
export GOSTORE_CLUSTER_SECRET=um-segredo-compartilhado
# node1:
GOSTORE_CLUSTER_SELF=http://node1:9000 gostore server \
  http://node1:9000/data/d{1...4} http://node2:9000/data/d{1...4}
# node2 (mesmos args, só muda o SELF):
GOSTORE_CLUSTER_SELF=http://node2:9000 gostore server \
  http://node1:9000/data/d{1...4} http://node2:9000/data/d{1...4}
```

8 discos → 4 dados + 4 paridade → sobrevive à perda de um nó inteiro. O tráfego
entre nós (`/gostore/internal/`) usa bearer token — rode em rede confiável ou
atrás de mTLS.

### VPS (systemd, bare-metal)

```bash
make build-linux                  # -> dist/gostore-linux-amd64
scp dist/gostore-linux-amd64 user@vps:/tmp/gostore
sudo install -m0755 /tmp/gostore /usr/local/bin/gostore
sudo useradd --system --home /var/lib/gostore --shell /usr/sbin/nologin gostore
sudo mkdir -p /var/lib/gostore/data && sudo chown -R gostore:gostore /var/lib/gostore
sudo cp deploy/gostore.service /etc/systemd/system/
sudo cp deploy/gostore.env /etc/gostore.env && sudo chmod 600 /etc/gostore.env
sudo nano /etc/gostore.env        # >>> troque GOSTORE_ROOT_PASSWORD <<<
sudo systemctl daemon-reload && sudo systemctl enable --now gostore
```

---

## CLI embutida

O mesmo binário é cliente — sem `mc`/`aws` separados:

```bash
gostore alias set gs https://storage.seu-dominio.com KEY SECRET
gostore mb   gs/meu-bucket
gostore cp   ./arquivo.zip gs/meu-bucket/
gostore cp   ./dir  gs/meu-bucket/dir -r
gostore ls   gs/meu-bucket
gostore cat  gs/meu-bucket/arquivo.zip | sha256sum
gostore rm   gs/meu-bucket/velho.txt -r
gostore stat gs/meu-bucket/arquivo.zip

gostore admin info     gs
gostore admin scrub    gs                 # dispara deep scrub
gostore admin readonly gs on
gostore admin snapshot gs meu-bucket      # snapshot / list / restore <id>
```

Aliases em `~/.gostore/aliases.json` (`GOSTORE_ALIAS_FILE` sobrescreve).

---

## Teste de carga

```bash
gostore bench gs/bench-bucket --duration 60s --concurrency 50 --size 4MiB
gostore bench gs/bench-bucket --mix get                # só leitura
gostore bench gs/bench-bucket -c 200 --size 64KiB      # muitos objetos pequenos
```

Sobe N goroutines fazendo `PUT → GET → DELETE` em loop e reporta ops/s,
MiB/s de PUT e GET, e latência p50/p95/p99. O bucket é criado se não existir;
as chaves `bench/…` são limpas no fim. Pra carga distribuída mais pesada, o
[`warp`](https://github.com/minio/warp) do MinIO também roda contra o gostore.

---

## Integrações

- **n8n** — node da comunidade em
  [`integrations/n8n-nodes-gostore/`](integrations/n8n-nodes-gostore/):
  objetos, buckets, URLs presigned, **transform de imagem** on-the-fly,
  **ingest keys** e admin (snapshot, backup, uso por pasta). Instale via
  *Settings → Community Nodes → `n8n-nodes-gostore`*. (O node S3 nativo do n8n
  também funciona — é só apontar o endpoint.)
- **Qualquer SDK / ferramenta S3** — AWS SDKs, `aws-cli`, `mc`, `rclone`,
  `s3fs`, Terraform (`aws` provider com `endpoints.s3`), Cyberduck. Ver
  [Compatibilidade S3](#compatibilidade-s3).

---

## Segurança

- **SigV4 obrigatório** por default (header, presigned, POST-form, streaming
  `aws-chunked` com verificação de assinatura por chunk).
- **IAM**: múltiplos usuários, service accounts (herdam a policy do pai ∩
  policy inline de sessão), engine de policy no estilo AWS (`Effect`,
  `Action`/`NotAction`, `Resource`, `Condition` com `String*`/`IpAddress`,
  `Principal`, **`deny` vence**), 5 canned policies, STS `AssumeRole`.
- **Bucket policy** com `Principal:*` habilita acesso anônimo/público
  controlado.
- **Criptografia em repouso**: SSE-S3 (`x-amz-server-side-encryption: AES256`)
  com AES-256-GCM em chunks de 64 KiB; DEK envelopada pela master key local ou
  pelo Vault Transit.
- **IAM cifrado em repouso**: o `store.json` (usuários, service accounts,
  secret keys) é gravado cifrado com a master key do KMS — um `store.json`
  vazado (backup, leitura de disco) é inútil sem a chave. Store plaintext de
  versões antigas é migrado automaticamente no primeiro boot.
- **Anti-spoof de IP**: `X-Forwarded-For` só é respeitado vindo de um proxy
  confiável (`GOSTORE_TRUSTED_PROXIES`, default loopback + ranges privados),
  então um cliente não falsifica o IP de origem usado nas policies/rate-limit.
- **Object Lock (WORM)** GOVERNANCE/COMPLIANCE + legal hold, com enforcement no
  delete e bypass só com `s3:BypassGovernanceRetention`.
- **Auditoria hash-encadeada** de toda mutação — adulteração é detectável.
- **`/gostore/metrics`** é aberto por default; feche com `GOSTORE_METRICS_TOKEN`.
- O tráfego interno de cluster usa bearer token — **rode em rede confiável ou
  atrás de mTLS.**

Reporte vulnerabilidades por [SECURITY.md](SECURITY.md) (ou issue privada).

---

## Estado do projeto

Feito do zero, em ordem de dependência, cada etapa rodando de verdade. Suíte de
testes verde (`go test ./...`).

### Completo

- API S3 (path-style + vhost), SigV4 (header/presigned/POST-form/streaming)
- Backend single-disk (`internal/object/fs`) e erasure coding N-discos
- Server pools (múltiplos sets, placement por hash, listagem com merge)
- Cluster multi-nó (grid multiplexado, lock por quorum) — *membership estático*
- Versionamento real + Object Lock (WORM) — **single-disk e erasure**
- IAM (usuários, service accounts, engine de policy, 5 canned) + STS `AssumeRole`
- SSE-S3 (AES-256-GCM) — **single-disk e erasure** (erasure: single-part)
- KMS externo via Vault Transit
- Lifecycle (expiração + transição/tiering), Tagging, Bucket Policy, CORS,
  Website
- Notificação de evento (webhook), Replicação async (local ou S3 remoto)
- Healing sob demanda + MRF + read-repair + deep scrub + auto-heal de disco novo
- Console web, CLI cliente, métricas Prometheus, log de atividade
- Dedup, compressão zstd, snapshots, backup automático, ingest keys, TTL por
  objeto, cache de objeto, pipeline de imagem, append, checksums adicionais,
  read-only mode, rate limit, admission control, uso por pasta

### Parcial / não feito

- **Cluster**: membership estático (reiniciar com a mesma topologia); sem
  rebalanceamento automático ao adicionar nós.
- **SSE-KMS** e **SSE-C** (só SSE-S3). Multipart no erasure não criptografa.
- **Grupos IAM**, `AssumeRoleWithWebIdentity` (OIDC/LDAP).
- Replicação sem fila de retry persistente (best-effort, 3 tentativas).

---

## Testes

```bash
go test ./...
```

Cobre: CRUD de bucket/objeto, listagem prefix/delimiter/paginação, multipart
round-trip + rejeição de part pequena, CopyObject; erasure — round-trip em
vários tamanhos, range straddling stripes, sobrevivência à perda de N/2 discos +
falha limpa além disso, bitrot detectado+reparado, heal reescreve shards,
fencing de revisão, server pools; dedup compartilha shards + GC; compressão
stream + range; tiering transição/leitura/delete; snapshot + restore;
self-backup incremental; IAM — engine de policy (wildcards, deny-vence, resource
scoping), enforcement por usuário, persistência; HTTP e2e — fluxo S3 assinado,
streaming chunked, bucket policy public-read, POST Object, conditional PUT,
append concorrente, TTL, checksums, cadeia de auditoria. O signer SigV4 do
console (Web Crypto) é validado ponta-a-ponta contra o servidor.

---

## Licença

**Apache License 2.0** — veja [LICENSE](LICENSE).

Uso comercial livre, sem copyleft de rede (ao contrário do AGPL do MinIO): você
pode rodar, modificar e embarcar o gostore em produtos fechados sem obrigação de
abrir seu código.

---

<sub>gostore não é afiliado à MinIO, Inc. ou à Amazon Web Services. "Amazon S3"
é marca da Amazon. A compatibilidade é com o protocolo, testada contra os SDKs
e ferramentas públicas.</sub>
