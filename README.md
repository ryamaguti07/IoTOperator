# IoT Operator

Operador de IoT do [TpM+](https://www.mdpi.com/1424-8220/25/16/5001): um custodiante da cadeia de custódia, um executor de smart contracts e um mediador entre o nível operacional e o nível executivo. A implementação segue o PoC em Python/Flask descrito no artigo e acrescenta uma porta HTTP só para envio de SLA, interpretado pelo Amazon Bedrock antes de virar contrato.

Referência: Yamaguti, R.; Ferreira, L. C. B. C.; Motta, L. L.; Assumpção, R. M.; Branquinho, O. C.; Iervolino, G.; Cardieri, P. *IoT and Blockchain for Support for Smart Contracts Through TpM*. Sensors 2025, 25, 5001. https://doi.org/10.3390/s25165001

## O que sobe no container

Um único container executa o nginx na frente do Flask (gunicorn).

| Porta no host | Porta no container | Uso |
| --- | --- | --- |
| 8080 | 80 | Interface e API do operador |
| 8090 | 8090 | Somente `GET/POST /sla` e `GET /health` |

O nginx da porta 8090 recusa qualquer outro caminho. O envio de SLA pela interface usa a API na porta 8080; sistemas externos podem falar direto com a 8090.

```text
sensor / operador  ->  nginx :80   ->  Flask
sistema de SLA     ->  nginx :8090 ->  Flask /sla -> Bedrock -> contrato na cadeia
```

## Papéis implementados

- **Custodiante.** Cada troca de custódia identifica a coisa por `usuário|equipamento|sala`, entra num bloco e fica cifrada com AES-256-GCM. A busca por equipamento usa SQLite, como o nível de armazenamento do PoC.
- **Executor.** O contrato padrão dispara quando o mesmo usuário fica com um equipamento por mais de 24 horas. Regras vindas de SLA (horas, disponibilidade, latência) também são avaliadas.
- **Mediador.** Uma disputa compara o pleito com o livro-razão e devolve um desfecho reproduzível, com os intervalos de custódia e as violações daquele contrato.
- **Consenso híbrido**, no processo do operador, como o artigo centraliza a validação: Proof-of-Authority na borda, líder Delegated Proof-of-Stake no cluster e finalização BFT com quórum de 3 em 4 validadores.

O conjunto de demonstração reproduz o formato publicado do PoC: 87 acessos, 3 salas, 3 usuários, o equipamento `84:66:39:91` como o mais usado e a sala 1 como a mais movimentada. Um quarto equipamento, `DE:MO:24:H0`, fica 30 horas em aberto para o contrato de 24 horas disparar.

## Subir

```bash
docker compose up --build
```

- Interface: http://localhost:8080
- Saúde da porta de SLA: http://localhost:8090/health

Contas da demonstração, só para este ambiente:

| Usuário | Senha | Papel |
| --- | --- | --- |
| ana | ana123 | operator |
| bruno | bruno123 | operator |
| carla | carla123 | admin |

O admin envia SLA, registra medições e encerra contrato. Operador e admin registram custódia. Os dois consultam equipamento, cadeia e disputas.

## SLA e Bedrock

`POST /sla` com Bearer token. O texto é interpretado e o contrato resultante é implantado na cadeia.

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"carla\",\"password\":\"carla123\"}" | python -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -s -X POST http://localhost:8090/sla \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"SLA de custódia\",\"document\":\"Entre a equipe operacional e a diretoria. O equipamento 84:66:39:91 não pode permanecer mais de 24 horas com o mesmo usuário. Disponibilidade mínima de 99.5%. Latência máxima de 200 ms. Penalidade: alertar o nível executivo.\"}"
```

`BEDROCK_MODE` controla a interpretação:

- `auto` (padrão): chama o Amazon Bedrock se houver credencial AWS; sem credencial, o interpretador local extrai horas, disponibilidade e latência e grava `interpretation_source: local_fallback`.
- `required`: responde erro se o Bedrock não produzir o contrato.
- `off`: usa só o interpretador local.

Modelo padrão: `amazon.nova-lite-v1:0` na região `us-east-1`. Troque com `BEDROCK_MODEL_ID` e `AWS_REGION`. Credenciais vazias são removidas na subida do container para o SDK usar perfil, role ou variáveis realmente preenchidas.

Uma medição que quebra o contrato:

```bash
curl -s -X POST http://localhost:8080/api/metrics \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"contract_id\":\"CONTRATO\",\"metric\":\"availability_percent\",\"value\":97}"
```

## API principal

Todas, exceto `POST /api/auth/login` e `GET /health`, exigem `Authorization: Bearer`.

| Método | Caminho | Função |
| --- | --- | --- |
| POST | `/api/auth/login` | Emite JWT de 8 horas |
| GET | `/api/status` | Altura da cadeia, consenso e modo do Bedrock |
| GET | `/api/equipment?q=` | Busca rápida por sala e custódia atual |
| POST | `/api/custody` | Assume equipamento em uma sala |
| POST | `/api/custody/return` | Devolve o equipamento |
| GET | `/api/chain` | Últimos eventos finalizados |
| GET | `/api/chain/verify` | Recalcula hashes, Merkle, votos BFT e AES |
| GET | `/api/contracts` | Contratos implantados |
| POST | `/api/contracts/<id>/complete` | Encerra um contrato |
| POST | `/api/metrics` | Informa medição e avalia a regra |
| POST | `/api/disputes` | Media um pleito com o livro-razão |
| POST | `/sla` e `/api/sla` | Interpreta um SLA e implanta o contrato |

Uma regra executável tem `metric`, `breach_if` (`>`, `>=`, `<`, `<=`), `threshold` e `action` (`flag_unauthorized_extended_use`, `alert_executive` ou `deactivate_user`).

## Exemplos de chamada

Os exemplos abaixo são PowerShell. O login devolve o JWT usado nas chamadas seguintes.

Envio de SLA pela porta 8090. A resposta traz `interpretation_source` (`bedrock` ou `local_fallback`) e o contrato implantado.

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/auth/login `
  -ContentType "application/json" `
  -Body '{"username":"carla","password":"carla123"}'

$sla = Invoke-RestMethod -Method Post -Uri http://localhost:8090/sla `
  -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer $($login.token)" } `
  -Body (@{
    title = "SLA de custódia"
    document = "Entre a equipe operacional e a diretoria. O equipamento 84:66:39:91 não pode permanecer mais de 24 horas com o mesmo usuário. Disponibilidade mínima de 99.5%. Latência máxima de 200 ms. Penalidade: alertar o nível executivo."
  } | ConvertTo-Json)

$sla | ConvertTo-Json -Depth 6
```

Leitura de sensor. No TpM+ isso é a tag RFID do equipamento vista numa sala, associada ao crachá de quem está autenticado. `84:66:39:91` é o osciloscópio e `room-1` é a Sala de teste 1. A resposta devolve o `thing_id` (`ana|84:66:39:91|room-1`) e o hash do bloco. A mesma custódia, do mesmo usuário na mesma sala, é recusada.

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/auth/login `
  -ContentType "application/json" `
  -Body '{"username":"ana","password":"ana123"}'

$leitura = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/custody `
  -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer $($login.token)" } `
  -Body '{"equipment_id":"84:66:39:91","room_id":"room-1"}'

$leitura | ConvertTo-Json -Depth 6
```

Cadeia. O `limit` define quantos eventos finalizados voltam, do mais recente para o mais antigo. Cada item traz o bloco, a ação (`custody`, `violation`, `contract_deploy`), o resumo, o líder do consenso e a camada `finalized`.

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/auth/login `
  -ContentType "application/json" `
  -Body '{"username":"ana","password":"ana123"}'

$cadeia = Invoke-RestMethod -Method Get -Uri "http://localhost:8080/api/chain?limit=12" `
  -Headers @{ Authorization = "Bearer $($login.token)" }

$cadeia | ConvertTo-Json -Depth 5
```

Verificação da cadeia, reusando o `$login` do exemplo anterior. Recalcula hashes, Merkle e votos BFT. Uma cadeia íntegra responde `valid: true` e a altura em `height`.

```powershell
Invoke-RestMethod -Method Get -Uri http://localhost:8080/api/chain/verify `
  -Headers @{ Authorization = "Bearer $($login.token)" }
```

## Variáveis

Veja `.env.example`. `JWT_SECRET` e `AES_KEY` vazios fazem o container gerar e guardar os segredos em `/data`. A chave AES aceita 32 bytes em hexadecimal (64 caracteres) ou base64 url-safe.

## Testes locais

```bash
pip install -r requirements.txt pytest
pytest
```

## Limites desta implementação

O consenso não é uma rede pública de mineradores. Os validadores, o líder DPoS e o quórum BFT rodam dentro do operador, que é onde o TpM+ concentra a finalização. O livro-razão é local e cifrado; a busca fica em SQL para manter a consulta de equipamento do PoC. Sem credencial da AWS o Bedrock não é chamado, e o contrato ainda é criado pelo interpretador local, com a origem indicada na resposta.
