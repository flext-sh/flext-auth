# FLEXT Auth

Servico de autenticacao e autorizacao para controle de acesso entre APIs, CLIs e componentes FLEXT.

Descricao oficial atual: "FLEXT Auth - Enterprise Authentication & Authorization Service".

## O que este projeto entrega

- Valida identidade e regras de acesso em pontos de entrada.
- Padroniza estrategias de autenticacao para multiplos contextos.
- Reduz risco de inconsistencias de seguranca entre projetos.

## Contexto operacional

- Entrada: credenciais, tokens e contexto de permissao.
- Saida: decisao de acesso e estado de autenticacao.
- Dependencias: flext-core e provedores de identidade settingsurados.

## Estado atual e risco de adocao

- Qualidade: **Alpha**
- Uso recomendado: **Nao produtivo**
- Nivel de estabilidade: em maturacao funcional e tecnica, sujeito a mudancas de contrato sem garantia de retrocompatibilidade.

## Diretriz para uso nesta fase

Aplicar este projeto somente em desenvolvimento, prova de conceito e homologacao controlada, com expectativa de ajustes frequentes ate maturidade de release.
