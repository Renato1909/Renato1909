# Política de segurança

## O que este repositório protege

Credenciais reais nunca devem existir no código-fonte ou no histórico deste repositório.
Três camadas verificam isso:

1. **CI** — [Guarda de segredos](.github/workflows/secret-scan.yml) roda `gitleaks` sobre todo o histórico,
   o [scanner próprio](tools/secret-scan.mjs) sobre todo o histórico e uma varredura antecipada
   nos arquivos acompanhados de cada PR.
2. **Regras locais** — [.gitleaks.toml](.gitleaks.toml) inclui o conjunto padrão e regras específicas
   do stack deste projeto (Supabase, Cloudflare, Expo/EAS, Brevo) e uma lista de permissões para
   fixtures de teste.
3. **Preparação do lado do cliente** — as chaves secretas ficam apenas no servidor, em variáveis de
   ambiente declaradas no arquivo de exemplo; o navegador e o aplicativo nunca recebem credencial
   administrativa.

## Como reportar uma vulnerabilidade

Abra uma issue apenas se ela não revelar a exploração. Para qualquer problema que possa ser
abusado antes da correção, use o e-mail de contato listado no perfil do GitHub e descreva o
problema sem publicar o payload de demonstração.

Escopo: código deste repositório e o serviço publicado correspondente. Bibliotecas de terceiros
devem ser reportadas ao mantenedor delas.

## Se uma credencial for commitada por engano

A ordem importa, e remover o arquivo do último commit não é suficiente:

1. **Rotacione ou revogue a credencial no provedor** antes de qualquer limpeza. Um valor que
   chegou ao Git é tratado como comprometido, mesmo que o repositório volte a ser privado, porque
   forks, caches e o feed de atividade podem reter o conteúdo.
2. Reescreva o histórico com `git filter-repo` (ou BFG) e force o envio das refs afetadas.
3. Comunique quem tem clones antigos para reclonar, e não apenas fazer `git pull`.
4. Solicite a remoção do cache antigo ao suporte do GitHub informando os hashes dos commits.

## O que não é vulnerabilidade

- Strings de fixture de teste e canários, como senhas falsas em `test/` e `e2e/`, endereços
  `@example.com`/`@example.test` e chaves de documentação tipo `AKIAIOSFODNN7EXAMPLE`.
- Arquivos `.env.example` e `.dev.vars.example` com campos vazios ou placeholders.
- URLs públicas, identificadores de canal, hashes de módulo em `go.sum` e `package-lock.json`.
