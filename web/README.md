# Abraham Operator UI

Interface Three.js integrada ao teamserver Abraham com dois modos de dados:

- **Demo:** preserva os 576 endpoints simulados, os oito andares, todas as vistas, filtros, telemetria e ações locais.
- **Ao vivo:** consulta sessões e resultados do canal de gestão em modo somente leitura. CPU e memória aparecem como `N/A`, pois o implant não fornece essas métricas. A posição no prédio é apenas uma projeção visual.

O chat usa a OpenAI Responses API. A chave e o token de gestão permanecem no processo Node; nenhum dos dois é enviado ao navegador ou incluído no contexto do modelo. A IA recebe metadados de sessões e até cinco resumos recentes por sessão, mas não possui endpoint para criar tarefas.

## Configuração

Crie `web/.env.local` com base em `.env.example`:

```dotenv
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-5-mini
ABRAHAM_MGMT_ADDR=127.0.0.1:9000
ABRAHAM_MGMT_TOKEN=
ABRAHAM_WEB_HOST=127.0.0.1
ABRAHAM_WEB_PORT=4173
```

Use em `ABRAHAM_MGMT_TOKEN` exatamente o valor passado ao teamserver por `--mgmt-token`. Se o teamserver estiver aberto no laboratório local, deixe-o vazio.

O servidor web aceita somente loopback. Para um teamserver remoto, execute a interface no mesmo host ou abra um túnel autenticado que encaminhe uma porta local para o listener de gestão remoto. No deploy `avln`, o listener é `127.0.0.1:9200`; ele não deve ser publicado diretamente na internet.

## Executar

Com o teamserver iniciado:

```console
cd web
npm start
```

Abra `http://127.0.0.1:4173`. A interface tenta entrar no modo ao vivo automaticamente; se o canal de gestão estiver indisponível, o modo demo continua funcionando. O botão no topo alterna os modos.

## API Local

As chamadas same-origin da UI enviam o header `X-Abraham-Client: operator-ui`;
requisições sem ele são recusadas para impedir uso cross-site do gateway local.

- `GET /operator-api/health`
- `GET /operator-api/sessions`
- `GET /operator-api/sessions/:id/results?limit=5`
- `POST /operator-api/assistant`

Não existe rota genérica de gestão. Shell, upload, persistência, coleta, credenciais, driver e demais capacidades continuam preservadas no teamserver e na TUI, mas não são expostas à IA nem à aplicação web.

## Controles Preservados

- Clique na fachada ou escolha um andar em Infraestrutura para isolá-lo.
- `B` restaura o prédio; `P` abre a planta; `V` seleciona; `H` move.
- `E` abre endpoints; `/` abre a busca; `?` ou `F1` abre a ajuda.
- Alt + botão direito abre o menu radial.
- As janelas continuam arrastáveis, redimensionáveis e acessíveis por teclado.
- Verificação e isolamento permanecem simulações locais e ficam desabilitados no modo ao vivo.

## Validação

```console
npm run check
npm test
```

Three.js está vendorizado em `dist/vendor`, portanto a interface não depende de um build para iniciar.
