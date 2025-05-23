# Miniprojeto: Análise Comparativa e Modificação do Algoritmo de Hash Leve LwHash

Este repositório contém a implementação e os materiais do miniprojeto para a disciplina de Tópicos Avançados em Computação, focado na análise e modificação do algoritmo de hash leve LwHash.

## Integrantes da Equipe

* André Carvalho
* Danilo Souza
* Igor C. Assunção
* Mariana Zanon
* Victor Macaúbas

## Descrição do Projeto

O projeto baseia-se no artigo "Design and Performance Analysis of a SPECK-Based Lightweight Hash Function" de Abdullah Sevin e Ünal Çavuşoğlu (2024). O LwHash original utiliza a cifra de bloco leve SPECK.

Neste miniprojeto, propomos uma variante do LwHash, denominada **LwHash-EMLw (Even More Lightweight)**, onde a cifra de bloco SPECK é substituída pela cifra de bloco leve RECTANGLE. O objetivo é realizar uma análise comparativa detalhada entre o LwHash original e o LwHash-EMLw, avaliando o impacto dessa substituição nas propriedades de segurança (efeito avalanche, distribuição estatística, resistência à colisão) e no desempenho (tempo de execução).

A metodologia de avaliação seguirá rigorosamente os testes e métricas descritos no artigo original para permitir uma comparação direta e conclusiva.

## Estrutura do Repositório

```
/
|-- main.cpp                # Arquivo principal para execução e testes iniciais
|-- utils.hpp               # Interface para funções utilitárias (XOR, rotações, conversões)
|-- utils.cpp               # Implementação das funções utilitárias
|-- padding.hpp             # Interface para o algoritmo de Padding (Algoritmo 1 do paper)
|-- padding.cpp             # Implementação do algoritmo de Padding
|-- speck.hpp               # Interface para a cifra de bloco SPECK
|-- speck.cpp               # Implementação da cifra de bloco SPECK
|-- rectangle.hpp           # Interface para a cifra de bloco RECTANGLE
|-- rectangle.cpp           # Implementação da cifra de bloco RECTANGLE
|-- ctr_mode.hpp            # Interface para o modo de operação CTR (Counter Mode)
|-- ctr_mode.cpp            # Implementação do modo CTR
|-- lwhash_core.hpp         # Interface para a estrutura principal do LwHash (Algoritmo 2 do paper)
|-- lwhash_core.cpp         # Implementação da estrutura LwHash (parametrizada para SPECK/RECTANGLE)
|-- Makefile                # Makefile para compilação do projeto em C++
|-- referencias_miniprojeto.bib # Arquivo BibTeX com as referências bibliográficas
|-- Relatorio_Miniprojeto.pdf # (Opcional) Versão final do relatório gerado pelo Overleaf
|-- README.md               # Este arquivo
```

## Como Compilar e Executar

### Pré-requisitos

* Um compilador C++ moderno (g++ ou Clang são recomendados, suportando C++17 ou superior).
* `make` (para usar o Makefile).

### Compilação

1.  Clone o repositório:
    ```bash
    git clone [URL_DO_SEU_REPOSITORIO]
    cd lwhash_project
    ```
2.  Use o Makefile para compilar o projeto:
    ```bash
    make
    ```
    Isso irá gerar um executável chamado `lwhash_app` (ou o nome definido no Makefile).

### Execução

Após a compilação, execute o programa:

```bash
./lwhash_app
```

O programa `main.cpp` atualmente executa alguns cálculos de hash de exemplo para LwHash (SPECK) e LwHash-EMLw (RECTANGLE).

### Limpeza

Para remover os arquivos objeto (`.o`) e o executável:

```bash
make clean
```

## Objetivos Detalhados

1.  Implementar a estrutura do LwHash conforme o artigo de referência.
2.  Implementar as cifras de bloco SPECK e RECTANGLE.
3.  Integrar a cifra RECTANGLE na estrutura LwHash, criando a variante LwHash-EMLw, com as devidas adaptações para o tamanho de bloco.
4.  Replicar os testes de segurança do artigo original:
    * Sensibilidade do valor de hash (Efeito Avalanche).
    * Análise estatística (Confusão e Difusão).
    * Distribuição dos valores de hash.
    * Resistência à colisão.
5.  Replicar o teste de desempenho (tempo de execução) do artigo original.
6.  Analisar e comparar os resultados obtidos para LwHash-SPECK e LwHash-EMLw.
7.  Documentar os achados em um relatório técnico (via Overleaf) e uma apresentação.

## Referência Principal

* Sevin, A.; Çavuşoğlu, Ü. Design and Performance Analysis of a SPECK-Based Lightweight Hash Function. *Electronics* **2024**, *13*, 4767. DOI: [10.3390/electronics13234767](https://doi.org/10.3390/electronics13234767)

## Status do Projeto (Exemplo - Atualizar conforme o progresso)

* [X] Definição da estrutura do projeto e do README.
* [X] Esqueleto do código C++ criado.
* [ ] Implementação completa da cifra SPECK.
* [ ] Implementação completa da cifra RECTANGLE.
* [X] Implementação da estrutura LwHash e modo CTR.
* [ ] Integração do RECTANGLE no LwHash-EMLw.
* [ ] Desenvolvimento dos scripts/funções de teste.
* [ ] Execução dos testes de segurança e desempenho.
* [ ] Análise dos resultados.
* [ ] Redação do relatório final e preparação da apresentação.

---
*(Este README pode ser atualizado conforme o projeto avança.)*
