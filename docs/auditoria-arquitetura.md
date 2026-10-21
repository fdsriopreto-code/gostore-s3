# gostore — auditoria de arquitetura (segurança, escalabilidade, confiabilidade)

Pente-fino em cima do código em produção. Separei em três blocos — **segurança**,
**escalabilidade** e **confiabilidade/disponibilidade** — e no fim tem uma lista
priorizada do que atacar primeiro.

Cada item de segurança crítico abaixo eu **reproduzi** com um teste contra o
servidor real (backend single-disk, que é o modo padrão do `docker run … server /data`),
e depois apaguei o teste. Não é teoria.

---

## 🔴 Segurança — crítico (corrigir antes de qualquer coisa)

### S1. CopyObject não autoriza a leitura da origem → vazamento entre buckets

`handleCopyObject` / `handleCopyObjectPart` leem o objeto de origem sem nunca
checar `s3:GetObject` nele. A autorização do request (`authorizeS3`) só olha o
**destino** (`PutObject` no bucket de destino), porque o roteador mapeia o método
`PUT com x-amz-copy-source` para a ação `s3:PutObject` sobre o path de destino.

Resultado confirmado: um usuário com permissão só de escrita/leitura no bucket
`mine` copia `secret/payroll.txt` (que ele **não** pode ler) para `mine/` e lê o
conteúdo. Qualquer objeto de qualquer bucket é exfiltrável por quem tenha escrita
em um único bucket.

- `internal/api/handlers_object.go:289` (`handleCopyObject`)
- `internal/api/handlers_multipart.go:55` (`handleCopyObjectPart`)
- A raiz é o mapeamento em `internal/api/authz.go:213` — copy vira `s3:PutObject`.

**Correção:** antes de copiar, rodar `authorizeS3`/`IsAllowed` com ação
`s3:GetObject` sobre `srcBucket/srcKey` para o `accessKey` do chamador (e, se
houver bucket policy, considerá-la). Sem isso, nenhuma outra proteção de IAM
vale.

### S2. Path traversal no `x-amz-copy-source` → leitura do banco de IAM (todas as senhas)

O `x-amz-copy-source` é só desescapado e partido no primeiro `/`
(`parseCopySource`, `handlers_object.go:496`). Não passa por `validObjectName`.
Com `x-amz-copy-source: /mine/../.gostore.sys/iam/store.json` o `CopyObject`
copia o arquivo interno do IAM para dentro de `mine/`, e aí é só dar GET.

Confirmado: retorno 200 com o `store.json` inteiro — **todos os usuários e
service accounts com `secretKey` em texto puro**. Ou seja, um traversal vira
comprometimento total do servidor.

Dois problemas somados aqui:
1. **Traversal**: origem (e destino) do copy não são validados contra `..` e
   contra o prefixo reservado `.gostore.sys/`.
2. **Segredos em texto puro**: `internal/iam/store.go` grava `secretKey` sem
   hash. Mesmo sem traversal, qualquer leitura indevida do volume (backup mal
   configurado, outro processo, etc.) entrega todas as credenciais.

**Correção:** validar `srcBucket`/`srcKey` (e `dstKey`) com as mesmas regras de
`validObjectName`/`validBucketName` — rejeitar `..`, prefixo `.gostore.sys/`,
nome de bucket reservado. E migrar o store de IAM para guardar um hash/derivação
da secret (ou no mínimo cifrar o blob com a master key do KMS).

### S3. Path traversal no DeleteObject / DeleteObjects → apaga arquivo fora do bucket

O `DeleteObject` single-disk (`internal/object/fs/object.go:333`) faz
`ensureBucket` e já parte pro `os.Remove(objDataPath)` **sem** `validObjectName`.
`objDataPath` é `filepath.Join(root, bucket, key)`, então `key = ../victim.txt`
resolve para fora do bucket. O `handleDeleteObjects` em lote
(`handlers_bucket.go`) passa as keys cruas direto pro backend.

Confirmado: `POST /mine?delete` com `<Key>../victim.txt</Key>` apagou um arquivo
na raiz do volume. Dá pra apagar `.gostore.sys/...` (IAM, config, formato de
disco) e derrubar/zerar o servidor.

**Correção:** `validObjectName` no começo de `DeleteObject` (e no `PutObject`
versionado também — conferir), e não só nos caminhos que já validam.

### S4. STS AssumeRole escala privilégio de service account para root

Um service account cujo policy inline só permite `s3:GetObject` em `mine/*`
chama `AssumeRole` e recebe credenciais temporárias que **perdem a restrição
inline** e passam a agir como o pai (root): leem `secret/payroll.txt` e chamam a
admin API (`/gostore/admin/v1/info`).

A causa: em `handleAssumeRole` (`handlers_sts.go`), quando o chamador é um service
account, `parent` vira o `ParentUser` (= root) e o STS herda os policies do pai;
o policy inline do service account **não** é propagado como teto do token. Ou
seja, o service account "sobe" para a conta pai inteira.

- `internal/api/handlers_sts.go:72` (resolução de `parent`)
- `internal/iam/iam.go:259` (`IsAllowed`: root passa direto se `Inline == nil`)

**Correção:** o token STS emitido por um service account tem que ser limitado
pela interseção (policy do pai ∩ inline do service account ∩ policy de sessão),
nunca escalar para o pai cru. Se o pai é root, o teto ainda precisa ser o inline
do service account.

### S5. Mapeamento de ação incompleto → bypass de autorização em sub-recursos

`s3Action` (`authz.go:150+`) só cobre um punhado de sub-recursos. O que não está
no switch cai no `default`:
- `PUT ?lifecycle`, `?website`, `?cors`, `?notification`, `?object-lock`,
  `?replication`, `?quota`, `?compression` → caem em `s3:CreateBucket`.
- Vários GET de sub-recurso → caem em `s3:ListBucket` ou `s3:GetObject`.

Confirmado: um usuário com **só** `s3:CreateBucket` conseguiu
`PutBucketLifecycle` em um bucket que não é dele (200) — e lifecycle com
`Expiration` apaga objetos. Então "poder criar bucket" vira "poder configurar
expiração/replicação/website em qualquer bucket".

**Correção:** mapear cada sub-recurso para a ação S3 correta
(`s3:PutLifecycleConfiguration`, `s3:PutBucketWebsite`, `s3:PutReplicationConfiguration`,
`s3:PutBucketObjectLockConfiguration`, etc.), e o `default` de escrita de
sub-recurso ser negado, não `CreateBucket`.

### S6. Pontos menores de segurança (ainda relevantes)

- **`clientIP` confia cegamente no `X-Forwarded-For`** (`authz.go`). Qualquer
  cliente manda o header e falsifica o IP de origem usado nas `Condition`
  `IpAddress` das policies e no rate-limit por IP anônimo. Só confie no XFF
  atrás de um proxy conhecido (lista de proxies confiáveis / usar só o último
  hop).
- **`GOSTORE_ALLOW_ANONYMOUS=1`** desliga **toda** a autorização para requests
  sem assinatura (`authz.go:78`). O README diz "só debug" — vale um aviso mais
  forte no boot (já tem Warn) e, idealmente, não permitir que ele valha para a
  admin API.
- **Tráfego de cluster com bearer token em rede confiável**: o README já diz
  "rode atrás de mTLS", mas o default é texto puro. Deixar explícito que sem
  mTLS/rede privada o segredo e os dados entre nós trafegam sem proteção.
- **STS SessionToken == AccessKeyId** (`handlers_sts.go`): o token é
  auto-descritivo e previsível; combinado com o fato de STS ser só em memória,
  está ok funcionalmente, mas não há revogação antes do expiry.

---

## 🟡 Escalabilidade

### E1. Listagem é O(bucket) por página — o maior limitador prático

O próprio `docs/comparacao-minio.md` já reconhece: cada página de
`ListObjectsV2` **re-percorre e re-ordena o bucket inteiro** (`walkKeys` +
`sort.Strings` em `internal/erasure/list.go`; mesma coisa no `fs/list.go`). Tem
o cache de listagem por TTL (`GOSTORE_LIST_CACHE_TTL`, 15s) que ameniza a
paginação rápida, mas:

- Num bucket com 1–5M objetos, cada walk materializa **todas** as keys em
  memória (`walkKeysMax = 2.000.000`) e ordena. Isso é CPU + RAM por listagem.
- Clientes que paginam devagar (além do TTL) pagam O(bucket) por página.
- Muitos backends de aplicação fazem `ListObjectsV2` com `prefix` por pasta —
  isso ajuda, mas o walk ainda desce a árvore inteira do prefixo.

**Impacto:** é aqui que ele "pesa" primeiro sob volume real de objetos. Não
derruba, mas a latência de LIST cresce linear com o bucket e a RAM sobe em
picos.

**Caminho:** cache de listagem persistido/incremental (estilo metacache do
MinIO) ou um índice por bucket. É trabalho grande; a mitigação barata é
documentar o limite e recomendar `prefix` + `max-keys` pequenos, e manter o
`GOSTORE_LIST_CACHE_TTL` ligado.

### E2. Transporte de cluster: 1 request HTTP por operação de disco

`RemoteDisk` faz um round-trip HTTP por `ReadAll`/`WriteAll`/`CreateFile`. Num
GET erasure que lê N shards de nós remotos, são N requests HTTP. Para single-node
e cluster pequeno em rede boa, tudo bem; para cluster com latência entre nós, o
overhead por operação domina. O README/doc já lista o grid multiplexado do MinIO
como o que falta. Não é urgente, mas é o teto de performance do modo cluster.

### E3. IAM/config são por-nó no cluster (consistência eventual de 30s)

`StartRefresh` recarrega IAM e bucketcfg a cada 30s a partir do store replicado.
Um usuário criado no nó A só aparece no nó B em até 30s, e dois nós podem
sobrescrever o blob um do outro (last-writer-wins por `UpdatedAt`) — não há
lock/CAS na escrita do `store.json`. Em cluster com escrita de IAM concorrente dá
pra perder alterações. Para a maioria dos casos (IAM muda pouco) é tolerável,
mas precisa estar documentado e, idealmente, serializar escritas de IAM.

### E4. Memória sob carga de upload

Tem admission control (`GOSTORE_MAX_INFLIGHT_BYTES`, default 512MiB) e rate
limit — bom. Vale validar que uploads multipart grandes e o `DeleteObjects` em
lote (lê corpo até 8MiB, 16 deleções paralelas) não acumulam além do teto sob
concorrência alta. O teto global existe, então o comportamento esperado é
`503 SlowDown`, não OOM — confirmar com um teste de carga `gostore bench` com
objetos grandes e muita concorrência.

---

## 🟢 Confiabilidade / disponibilidade ("ele cai?")

### C1. Single-disk é ponto único de falha — e é o default do Docker

O `Dockerfile`/`docker-compose.yml` sobem `server /data` (single-disk). Nesse
modo **não há** erasure coding, nem quorum, nem redundância: um disco corrompido
ou um unlink indevido (ver S3) derruba dados. O bitrot/scrub só protege de
corrupção silenciosa se houver paridade — em single-disk ele detecta mas não
repara.

**Mensagem pro usuário:** se os sistemas em produção estão rodando o default
Docker, eles estão em single-disk. "Nunca cair" exige, no mínimo, modo erasure
(`server /data/d{1...4}`) em discos/mounts separados, e idealmente cluster
multi-nó. O README explica isso, mas o default do compose não deixa óbvio que
single-disk = sem redundância.

### C2. Persistência do volume

Já tem proteção boa: aviso no boot quando o volume nasceu vazio e
`GET /gostore/health/persistence`. Isso cobre o erro clássico de PaaS (volume não
montado → tudo some no redeploy). Manter e destacar.

### C3. Durabilidade de escrita

`write-tmp → fsync → rename` + fsync do diretório pai é o certo. `GOSTORE_FSYNC=0`
troca durabilidade por throughput e já avisa no boot. Ok.

### C4. Graceful shutdown e locks

Shutdown tem timeout de 15s e cancela contextos. No dsync-lite do cluster, a doc
já aponta que a aquisição de lock é tentativa única (sem retry/backoff) e que a
operação em andamento **não** é abortada se o refresh falhar — isso pode deixar
um lock "fantasma" até o TTL expirar, ou permitir escrita concorrente após perda
de quorum. Em single-node não afeta; em cluster é um risco de correção sob
partição de rede.

### C5. Selftest e health

`/gostore/health/selftest` faz round-trip real (write/read/verify/delete) e tem
`live`/`ready`/`cluster`. Cobertura de health boa para orquestradores.

---

## Prioridade (o que fazer primeiro)

1. **S2 + S3 (traversal)** — validar nome de objeto/bucket em copy-source,
   destino de copy e delete. É a correção mais barata e fecha "ler o IAM / apagar
   arquivos de sistema". Faço isso em poucas linhas se você autorizar.
2. **S1 (autorizar origem do copy)** — fecha o vazamento entre buckets.
3. **S4 (STS não escalar)** — limitar o token à interseção de policies.
4. **S5 (mapa de ações)** — mapear cada sub-recurso para a ação S3 correta.
5. **Segredos de IAM em texto puro (parte do S2)** — hash/cifra do store.
6. **C1** — deixar explícito no compose/README que o default é sem redundância;
   recomendar erasure/cluster para produção.
7. **E1 (listagem O(bucket))** — médio prazo; é o limite de escala real.

As de segurança (1–5) são todas em código de API/IAM e dá pra corrigir com
testes de regressão cobrindo cada bypass. Me diz se quer que eu já comece pelos
traversals (S2/S3) — são contidas e de baixo risco.
