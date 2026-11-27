# Política de segurança

## Como relatar uma vulnerabilidade

Não abra issue pública. Use **Security → Report a vulnerability** neste repositório
(relato privado do GitHub). Inclua:

- o que é afetado (rota, módulo, contêiner) e a versão ou o commit;
- como reproduzir, com o menor caso possível;
- o impacto que você observou ou espera.

O dono do repositório responde pelo mesmo canal. A correção sai num PR com teste de
regressão, e o relato só é divulgado depois que a correção estiver na `main`.

## Versões suportadas

Só a `main` recebe correções.

## O que a esteira verifica

Cada push e PR passa por lint, testes, SAST (Bandit e Semgrep), varredura de segredos
(gitleaks), SCA e IaC (Trivy), lint de Dockerfile (hadolint) e gera SBOM (Syft).
Detalhes, limites conhecidos e o que é risco aceito estão em
[`docs/devsecops.md`](docs/devsecops.md).
