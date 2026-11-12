# RepoGuard

O RepoGuard responde se um repositório público do GitHub está **apto** para clonagem, se deve ser **revisado**, ou se **não deve ser clonado**. A consulta usa só a API do GitHub. Não há `git clone` e nenhum arquivo do repositório é executado.

O veredito é uma soma de sinais. Ele não prova que o código é seguro nem que é malware.

## Uso

Requer Python 3.11 ou mais novo.

Na pasta do projeto:

```powershell
.\repoguard owner/repo
.\repoguard owner/repo -r main
.\repoguard owner/repo -j
```

`scan` continua aceito (`.\repoguard scan owner/repo`), mas não é necessário. `-r` é `--ref` e `-j` é `--json`.

Para ter o comando em qualquer pasta:

```powershell
py -m pip install -e .
repoguard owner/repo
```

Um token pessoal aumenta o limite de requisições. Sem ele, a API anônima permite cerca de 60 consultas por hora. O token é lido de `GITHUB_TOKEN` e não é impresso.

```powershell
$env:GITHUB_TOKEN = "ghp_seu_token"
```

Também vale uma URL `git@github.com:owner/repo.git`. Em URL com `/tree/branch/pasta`, o branch usado é o primeiro segmento. Para um branch que contém barra, use `--ref`.

## Códigos de saída

| Código | Veredito |
| --- | --- |
| 0 | Apto |
| 2 | Revisar |
| 3 | Não clonar |
| 1 | Erro: URL inválida, repositório inacessível ou limite da API |

A nota vai de 0 a 100. Crítico vale 40, alto 25, médio 10, baixo 4 e info 0. **Não clonar** se houver achado crítico ou nota igual ou acima de 70. **Revisar** se houver achado alto ou nota igual ou acima de 30. Nos outros casos, o veredito é **apto**.

## O que é lido

Uma chamada traz o repositório, outra a conta do dono, outra os commits recentes, outra as cinco releases mais novas e outra a árvore do branch. O conteúdo vem só de arquivos de risco: workflows, `package.json`, manifestos Python, `requirements*.txt`, `Dockerfile`, `Makefile`, README, `action.yml`, scripts de instalação JavaScript e scripts de shell ou PowerShell na raiz ou em `scripts/`.

No máximo 30 conteúdos são lidos. Arquivo acima de 100 mil bytes não é lido e entra no relatório como não inspecionado. Árvore cortada pela API também vira achado. Trechos citados são curtos e não carregam sequência de cor do arquivo.

## Sinais

- Repositório ou conta muito recentes, um único commit, fork, ausência de licença e repositório arquivado. Sozinhos não bloqueiam a clonagem.
- Nome do dono ou do repositório com alfabeto misturado, caractere invisível, ou grafia muito parecida com um projeto conhecido.
- Executável, biblioteca, script de Windows ou imagem de disco versionados, e nome com extensão dupla.
- Workflow que encaminha download para um shell, `pull_request_target` com checkout do código do pull request, dado de evento interpolado em `run`, permissão `write-all`, e action sem SHA.
- `preinstall`, `install`, `postinstall` ou `prepare`. Num repositório pouco conhecido, o hook sozinho pede revisão. Com rede, ofuscação, destino de coleta, canal de shell ou indicador de minerador, o veredito é não clonar. Também entram base64 encaminhado para execução, `setup.py` que chama o sistema, e dependência `git+http` ou por URL.
- Script ou instalação que aponta para caminho de chave SSH, credencial de nuvem, token do npm, carteira ou perfil de navegador.
- README que pede `curl` encaminhado ao shell, desligar antivírus, Defender, SmartScreen ou Gatekeeper, ou colar um token.
- Anexo de release com executável ou imagem de disco. O arquivo não é baixado.

Idade de pelo menos 180 dias e pelo menos 50 estrelas atenuam o one-liner do README, a action sem SHA, a conta nova e o hook de instalação sem rede. Não atenuam hook com rede, ofuscação, vazamento, leitura de credencial, chave privada, `pull_request_target` com checkout, binário, extensão dupla, nome disfarçado ou imitação de projeto conhecido.

Um README com `curl` encaminhado ao shell pesa mais quando o repositório tem menos de 30 dias e menos de 10 estrelas.

## JSON

`--json` imprime o `ScanReport`: `repo`, `html_url`, `ref`, `verdict` (`apto`, `revisar` ou `nao_clonar`), `risk_score`, `findings` e `stats`. Esse objeto é o contrato para uma interface futura. O núcleo importável é `repoguard.scan`.

## Limites

Não há servidor web, clone mesmo sem hooks, execução de instalador, banco de hashes ou análise de dependência transitiva. Repositório fora do GitHub é recusado. A árvore e os arquivos públicos não mostram hooks locais do Git, segredos que só aparecem depois do clone, nem o que um script faria se fosse executado.

## Testes

Os testes usam respostas gravadas e não chamam a API.

```powershell
$env:PYTHONPATH = "src"
py -m unittest discover -s tests
```
