# Esteira DevSecOps

Como o código chega na `main`, o que cada verificação bloqueia e qual risco está
aceito, com prazo. Vale para o repositório privado; o público (BluePhish) não
recebe esta esteira por aqui.

## Os dois workflows

| Workflow | Job | Bloqueia | Relata |
|---|---|---|---|
| `python-app.yml` | ThePhish app (Python 3.14) | flake8 (E9, F63, F7, F82), compilação, suíte inteira, cobertura ≥ 58% (linha de base: 60%) | flake8 completo, `coverage.xml` |
| `python-app.yml` | Docker image | build da imagem, suíte dentro dela | Trivy da imagem, SBOM CycloneDX da imagem |
| `security.yml` | Segredos | gitleaks no histórico inteiro | — |
| `security.yml` | SAST | Bandit (severidade e confiança altas), Semgrep com as regras de `.semgrep/` | Bandit completo, Semgrep `p/python` e `p/flask` |
| `security.yml` | SCA, IaC | Trivy fs (dependências, Dockerfiles, segredos) ALTA/CRÍTICA fora da linha de base; hadolint | Trivy fs completo, SBOM CycloneDX do código |

Os dois rodam em push na `main` e em `agent/**`, e em PR para a `main`. O de
segurança também roda toda segunda às 06:00 UTC, porque vulnerabilidade nova
aparece sem commit nenhum.

## Princípios aplicados

- **Ações fixadas por SHA de commit**, com a tag no comentário. Uma tag pode ser
  movida por quem controla o repositório da ação; um SHA não. O Dependabot
  (`github-actions`) atualiza SHA e comentário juntos.
- **Imagens de ferramenta por digest** (`imagem@sha256:…`), pelo mesmo motivo. O
  Trivy está fixado em 0.62.1, de antes dos incidentes de cadeia de suprimentos
  que atingiram as tags do `trivy-action` e imagens do Trivy em 2026: não use
  `aquasecurity/trivy-action` por tag.
- **Menor privilégio**: `permissions: contents: read` nos dois workflows, e
  `persist-credentials: false` no checkout. Nenhum job escreve no repositório e
  nenhum usa segredo.
- **Concorrência**: um push novo cancela a execução anterior da mesma branch, nunca
  na `main`.
- **Gate que nasce verde sem esconder a dívida**: o que já existia quando o gate
  entrou está numa linha de base com motivo e prazo (`.trivyignore.yaml`,
  `.gitleaksignore`); qualquer achado novo bloqueia. Quando o prazo vence, o CI
  volta a falhar para obrigar a revisão.

## Regras do projeto no Semgrep

`.semgrep/bluephish.yml` roda offline e bloqueia:

- `verify=False` fixo no código (a validação TLS só se desliga por destino, na configuração);
- `yaml.load` sem `SafeLoader`, `pickle`/`marshal`;
- `shell=True`, `eval`/`exec`;
- `jwt.decode` sem `algorithms=` (confusão de algoritmo);
- `debug=True` em `app.run`/`socketio.run`.

As regras da casa que já têm teste (nenhum módulo abre o `configuration.json`
direto, toda rota no mapa de perfis, o analisador que falha dá `info`) continuam nos
testes, que são o gate mais forte.

## Risco aceito (prazo: 28/02/2027)

**Dependências: nenhuma.** Com a migração para o Python 3.14 (27/11/2026) o lock
foi de 32 ALTA/CRÍTICA para 0, e `.trivyignore.yaml` não tem mais exceção de
dependência. Duas versões entraram antes do cooldown de 30 dias por correção de
segurança (dnspython 2.9.2, soupsieve 4.0.0); estão no cabeçalho do lock.

**Contêineres como root (Trivy DS002).** Usuário sem privilégio, `cap_drop` e
`read_only` precisam de teste com o nginx e a API rodando. Já entrou
`no-new-privileges` nos três contêineres.

**Imagem.** A base `python:3.14-slim-trixie` é mantida; o build faz
`apt-get upgrade` e tira o `pip` da imagem final (as cópias vendorizadas de urllib3,
msgpack e setuptools dele eram os únicos achados ALTA da base). O Trivy da imagem
agora é gate: ALTA/CRÍTICA com correção disponível falha o job `Docker image`.

## Achados de segredo

O job `Segredos (gitleaks, histórico inteiro)` varre todos os commits. Achados já triados
(falsos positivos, com o motivo) ficam em `.gitleaksignore`. Um achado real não vai para essa
lista: a credencial é trocada na origem antes, e só então o achado é anotado.

Nenhum arquivo de configuração versionado carrega chave real: os de serviços de terceiros
(TheHive, Cortex) saíram do repositório, e as chaves da aplicação (chave mestra do cofre,
senha do PostgreSQL) são geradas pelo `setup.sh` em `docker/secrets/`, que o git ignora.

## Recomendações não aplicadas (precisam do dono do repositório)

Proteção da `main` (Settings → Branches, ou Rulesets):

- exigir PR, com 1 aprovação de CODEOWNER e descarte de aprovação velha em push novo;
- exigir os checks `ThePhish app (Python 3.14)`, `Docker image (build + test suite inside it)`,
  `Segredos (gitleaks, histórico inteiro)`, `SAST (Bandit e Semgrep)` e
  `SCA, IaC e segredos no código (Trivy)`, com a branch atualizada;
- bloquear force-push e exclusão da `main`; exigir histórico linear se preferir squash;
- ligar o relato privado de vulnerabilidades (Settings → Security), que o `SECURITY.md` cita.

O que depende de plano pago no GitHub, num repositório privado:

- **CodeQL e upload de SARIF para o Code scanning** exigem GitHub Code Security
  (Advanced Security). Sem ele, a esteira deixa os relatórios como artefatos.
- **Attestations de build (`actions/attest-build-provenance`)** em repositório privado
  exigem GitHub Enterprise Cloud.
- **Assinatura com cosign** só faz sentido quando a imagem for publicada num registro
  (GHCR). Hoje ela é construída no servidor pelo `setup.sh`. Quando publicar: cosign
  keyless por OIDC (`id-token: write` só nesse job) e attestation do SBOM.

O Python foi do 3.8 (EOL) para o 3.14, a minor mais recente já madura (suporte de
segurança até 2030). A 3.15 fica para uma migração própria, quando as wheels das
dependências compiladas existirem.

## Como rodar localmente

```
docker run --rm -v "$PWD:/repo" -w /repo --entrypoint sh zricethezav/gitleaks:v8.24.3 -c 'git config --global --add safe.directory /repo && gitleaks git --redact /repo'
docker run --rm -v "$PWD:/src" -w /src aquasec/trivy:0.62.1 fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --ignorefile .trivyignore.yaml /src
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.131.0 semgrep scan --metrics=off --config .semgrep/ --error --exclude 'test_*.py' app
pip install bandit==1.8.6 && bandit -q -r app -x 'app/test_*.py' -lll -iii
```
