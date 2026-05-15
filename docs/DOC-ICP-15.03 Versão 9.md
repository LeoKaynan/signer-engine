<!-- START OF PAGE 1 -->

INSTRUÇÃO NORMATIVA ITI N° 03, DE 12 DE FEVEREIRO DE 2021

Aprova a versão revisada e consolidada do documento Requisitos das Políticas de Assinatura Digital na ICP-Brasil DOC-ICP-15.03.

O DIRETOR-PRESIDENTE DO INSTITUTO NACIONAL DE TECNOLOGIA DA INFORMAÇÃO, no uso das atribuições que lhe foram conferidas pelo inciso VI do art. 9º do anexo I do Decreto nº 8.985, de 8 de fevereiro de 2017, pelo art. 1º da Resolução nº 33 do Comitê Gestor da ICP-Brasil, de 21 de outubro de 2004, e pelo art. 2º da Resolução nº 163 do Comitê Gestor da ICP-Brasil, de 17 de abril de 2020,

CONSIDERANDO a determinação estabelecida pelo Decreto nº 10.139, de 28 de novembro de 2019, para revisão e consolidação dos atos normativos inferiores a decreto, editados por órgãos e entidades da administração pública federal direta, autárquica e fundacional,

RESOLVE:

Art. 1º Esta Instrução Normativa aprova a versão revisada e consolidada do documento Requisitos das Políticas de Assinatura Digital na ICP-Brasil (DOC-ICP-15.03).

Art. 2º Fica aprovada a versão 8.0 do documento DOC-ICP-15.03 – Requisitos das Políticas de Assinatura Digital na ICP-Brasil, anexa a esta Instrução Normativa.

Art. 3º Ficam revogadas:

I - a Instrução Normativa nº 03, de 09 de janeiro de 2009;
II - a Instrução Normativa nº 03, de 22 de março de 2012;
III - a Instrução Normativa nº 10, de 05 de julho de 2012;
IV - a Instrução Normativa nº 14, de 19 de setembro de 2012;
V - a Instrução Normativa nº 07, de 25 de agosto de 2015;
VI - a Instrução Normativa nº 03, de 01 de junho de 2016;
VII - a Instrução Normativa nº 06, de 15 de julho de 2016;
VIII - a Instrução Normativa nº 03, de 23 de fevereiro de 2017; e
IX - a Instrução Normativa nº 08, de 29 de maio de 2018.

Art. 4º Esta Instrução Normativa entra em vigor em 1º de março de 2021.

CARLOS ROBERTO FORTNER

<!-- END OF PAGE 1 -->
<!-- START OF PAGE 2 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

ANEXO

# REQUISITOS DAS POLÍTICAS DE ASSINATURA

# DIGITAL NA ICP-BRASIL

# DOC-ICP-15.03

Versão 9.1

(Redação dada pela Instrução Normativa ITI nº 34, de 2025)

17 de julho de 2025

(Redação dada pela Instrução Normativa ITI nº 34, de 2025)

<!-- END OF PAGE 2 -->
<!-- START OF PAGE 3 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# SUMÁRIO

CONTROLE DE ALTERAÇÕES...3
LISTA DE SIGLAS E ACRÔNIMOS...6
LISTA DE TABELAS...7

1 INTRODUÇÃO...9
2 CONTEÚDO GERAL DE UMA POLÍTICA DE ASSINATURA...10
2.1 Identificador da Política de Assinatura (6.1, 8.2)...10
2.2 Data de Emissão (5, 8.2)...10
2.3 Nome da Entidade Emissora da Política de Assinatura (6.1, 8.2)...10
2.4 Campo de Aplicação (6.1, 8.2)...10
2.5 Política de Validação da Assinatura (6.2, 8.3)...10
2.6 Informações Adicionais sobre a Política de Assinatura (6.11, 8.2)...17
3 DOCUMENTOS ICP-BRASIL REFERENCIADOS...18
4 BIBLIOGRAFIA...19

ANEXO 1...20
1 POLÍTICAS DE ASSINATURA-PADRÃO ICP-BRASIL...20

ANEXO 2...39
1 POLÍTICA-PADRÃO AD-RB BASEADA EM CADES...39
2 POLÍTICA-PADRÃO AD-RT BASEADA EM CADES...44
3 POLÍTICA-PADRÃO AD-RV BASEADA EM CADES...50
4 POLÍTICA-PADRÃO AD-RC BASEADA EM CADES...56
5 POLÍTICA-PADRÃO AD-RA BASEADA EM CADES...63
6 POLÍTICA-PADRÃO AD-RB BASEADA EM XADES...70
7 POLÍTICA-PADRÃO AD-RT BASEADA EM XADES...75
8 POLÍTICA-PADRÃO AD-RV BASEADA EM XADES...81
9 POLÍTICA-PADRÃO AD-RC BASEADA EM XADES...88
10 POLÍTICA-PADRÃO AD-RA BASEADA EM XADES...95
11 POLÍTICA-PADRÃO AD-RB BASEADA EM PADES...102
12 POLÍTICA-PADRÃO AD-RT BASEADA EM PADES...107
13 POLÍTICA-PADRÃO AD-RC BASEADA EM PADES...113
14 POLÍTICA-PADRÃO AD-RA BASEADA EM PADES...120

ANEXO 3...127

GERENCIAMENTO DE POLÍTICAS DE ASSINATURA NA ICP-BRASIL...127
1 INTRODUÇÃO...127
2 ADMINISTRAÇÃO E CICLO DE VIDA DE UMA PA...127
3 APROVAÇÃO DE UMA PA...128
4 PUBLICAÇÃO DA PA E DA LPA...128
5 PRORROGAÇÃO DA VALIDADE DE UMA PA APROVADA...128
6 REVOGAÇÃO DE UMA PA...129
7 PROCEDIMENTOS PARA CRIAÇÃO E VERIFICAÇÃO DA LPA...129

ANEXO 4...130

EXTENSÕES DE POLÍTICAS DE ASSINATURA PARA PADES...130
1 INTRODUÇÃO...130
2 EXTENSÕES...130

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 3 -->
<!-- START OF PAGE 4 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

CONTROLE DE ALTERAÇÕES

|  Ato que aprovou a alteração | Item alterado | Descrição da alteração  |
| --- | --- | --- |
|  IN ITI n°34, de 17.07.2025
Versão 9.1 | Anexo 2 – Políticas PAdES | Inclusão de novas versões das Políticas de Assinatura PAdES.  |
|  IN ITI n°33, de 12.06.2025
Versão 9.0 | 1.7 e Anexo 2 | Inclusão de novas versões de Políticas de Assinatura.  |
|  IN ITI n° 03, de 12.02.2021
Versão 8.0 |  | Revisão e consolidação conforme Decreto n° 10.139, de 28 de novembro de 2019.  |
|  IN n° 08, de 29.05.2018.
Versão 7.4 | 1.10, 2.5.2.1.1.2, 2.5.2.1.1.3; Anexo 1: nota 9, Tabelas A.2, A.3, A.4, A.5, A.6, A.7, A.8, A.9, A.10, A.11, A.12, A.13, A.15 (removida) e A.17 (removida), Nota 1 da Tabela A.22; Anexo 2. | Alteração nos atributos proibidos e opcionais.
Tratamento de múltiplas referências no signingCertificate.
Inclusão de novas versões de Políticas de Assinatura.  |
|  IN n° 03, de 23.02.2017.
Versão 7.3 | Itens 2, 2.5.2.1.1.2 e 2.5.2.1.1.3; Tabelas A.9 e A.11; anexos 1, 3 e 4. | Alteração nas condições de obrigatoriedade dos atributos do Carimbo do Tempo. Disponibilização no repositório do ITI das especificações ASN.1 e XML da LPA e do ASN.1 das extensões PAdES.
Ajustes de texto para facilitar o entendimento.  |
|  IN n° 06, de 15.07.2016.
Versão 7.2 | Tabelas A.20 e anexos 2 e 4. | Ajustes nas políticas PAdES, correção da entrada Cert do dicionário VRI. Novas versões das políticas PAdES AD-RC e AD-RA.  |
|  IN n° 03, de 01.06.2016.
Versão 7.1 | Tabelas A.6, A.8, A.10, A.12 e A.16, anexos 2, 3 e 4. | Ajustes nas políticas PAdES e inclusão da raiz V5 em todas as Políticas de Assinatura.  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 4 -->
<!-- START OF PAGE 5 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

|  Ato que aprovou a alteração | Item alterado | Descrição da alteração  |
| --- | --- | --- |
|  IN n° 07, de 25.08.2015. Versão 7.0 | 1.4, 1.10 e 4.4; anexos 1, 2 e 4; tabelas A.14, A.15, A.16, A.17, A.18, A.19, A.20 e A.21. | Regulamentação PAdES  |
|  IN n° 14, de 19.09.2012 Versão 6.1 | Anexo 2, capítulos 5, 6, 7, 8, 9 e 10. | Inclui as definições da versão 2.2 da PA  |
|  IN n° 10, de 05.07.2012 Versão 6.0 | Anexo 1, item 1; Anexo 2, capítulos 5, 6, 7, 8, 9 e 10 Anexo 3, item 4 e 7 | Melhorias propostas pelo Grupo de trabalho de Revisão do padrão brasileiro de assinatura digital.  |
|  IN n° 03, de 22.03.2012 Versão 5.0 | Anexo 2 – Item 1 de todas as políticas XAdES Inclui as Notas 1 a 4 no Item 1 do Anexo 1. | Geradas novas políticas de assinatura versão 2.1 para XAdES. As notas contêm esclarecimentos e recomendações de codificação de atributos das políticas de assinaturas baseada em CAdES.  |
|  IN n° 02, de 06.03.2012 Versão 4.0 | Anexo 1 - Tabela A.2 Anexo 2 - Todas as políticas CAdES Item 5.2.1.1.2 | Corrigido atributo assinado obrigatório id-aa-signingCertificateV2 para a versão 2.0. Geradas novas políticas de assinatura versão 2.1 para CAdES.  |
|  IN n° 05, de 22.12.2011 Versão 3.0 | Item 1, Nota 1 e Anexo 2. Anexo 1, Tabelas A2 a A13 | Itens não citados nas políticas de assinatura DEVEM ser considerados como itens proibidos. Retirados todos os itens assinalados como “não se aplica”. Corrigido as propriedades XAdES citadas incorretamente; Corrigido o título da coluna central das Tabelas; Alterado o campo carimbo do tempo na política AD-RB de opcional para “não deve”;  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
4

<!-- END OF PAGE 5 -->
<!-- START OF PAGE 6 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

|  Ato que aprovou a alteração | Item alterado | Descrição da alteração  |
| --- | --- | --- |
|   | Anexo 2, Todas as políticas. | Retirado a obrigatoriedade do uso dos atributos referentes a certificado de atributo;
Corrigido os termos referentes à *timestamp* nas tabelas.  |
|   |  Item 5.2.1.1.5 | Inclusão da versão 2.0 que implementa a cadeia V2 da AC Raiz para todas as políticas de assinatura ICP-Brasil.  |
|   |  Anexo 3, item 4.2 | Obrigatoriedade de manter o certificado do signatário no caminho de certificação.  |
|   |  Item 7.4 | Corrigido endereço do repositório de publicação da LPA.  |
|   |   | Inclusão de codificação da LPA em ASN.1 e XML.  |
|  IN n° 03, de 31.03.2010
Versão 2.0 | Diversos | Atualização de padrões de assinatura.  |
|  IN n° 03, de 09.01.2009
Versão 1.0 | Diversos | Criação do DOC-ICP-15.03.  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 6 -->
<!-- START OF PAGE 7 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# LISTA DE SIGLAS E ACRÔNIMOS

|  SIGLA | DESCRIÇÃO  |
| --- | --- |
|  AC | Autoridade Certificadora  |
|  ACT | Autoridade de Carimbo do Tempo  |
|  CAdES | CMS Advanced Electronic Signatures  |
|  CMS | Cryptographic Message Syntax  |
|  DSS | Document Security Store  |
|  ETSI | European Telecommunication Standard Institute  |
|  ICP-Brasil | Infraestrutura de Chaves Públicas Brasileira  |
|  ITI | Instituto Nacional de Tecnologia da Informação  |
|  LCR | Lista de Certificados Revogados  |
|  LPA | Lista de Políticas de Assinatura Aprovadas  |
|  OCSP | Online Certificate Status Protocol  |
|  PA | Política de Assinatura  |
|  PAdES | PDF Advanced Electronic Signatures  |
|  PDF | Portable Document Format  |
|  RFC | Request For Comments  |
|  VRI | Validation Related Information  |
|  XAdES | XML Advanced Electronic Signatures  |
|  XML | Extensible Markup Language  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 7 -->
<!-- START OF PAGE 8 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
N° 1

# LISTA DE TABELAS

Tabela A.1: Abreviações utilizadas. ... 20
Tabela A.2: Atributos assinados no SignerInfo do Assinante ... 22
Tabela A.3: Presença de atributos não-assinados no SignerInfo do signatário ... 23
Tabela A.4: Presença de atributos assinados no SignerInfo de “contra assinatura” ... 24
Tabela A.5: Presença de atributos não-assinados no SignerInfo de “contra assinatura” ... 24
Tabela A.6: Presença de atributos assinados no TimeStampToken de “carimbo do tempo de conteúdo” ... 25
Tabela A.7: Presença de atributos não-assinados no TimeStampToken de “carimbo do tempo de conteúdo” ... 25
Tabela A.8: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura” ... 26
Tabela A.9: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura.” ... 27
Tabela A.10: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo das referências” ... 28
Tabela A.11: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo das referências” ... 29
Tabela A.12: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo de arquivamento” ... 30
Tabela A.13: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo de arquivamento” ... 30
Tabela A.14: Atributos assinados no SignerInfo do Assinante para assinaturas PAdES ... 31
Tabela A.15: Presença de atributos não-assinados no SignerInfo do signatário para assinatura PAdES ... 32
Tabela A.16: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura” para assinaturas PAdES ... 33
Tabela A.17: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura” para assinaturas PAdES ... 34
Tabela A.18: Presença das entradas do dicionário de assinaturas do PAdES ... 35
Tabela A.19: Presença das entradas do dicionário DSS do PAdES ... 36
Tabela A.20: Presença das entradas do dicionário VRI do PAdES ... 37
Tabela A.21: Presença das entradas do dicionário de assinatura do Document Timestamp do PAdES ... 38
Tabela A.22: Presença de dicionários PDF relacionados às assinaturas PAdES ... 38
Tabela A.4.1 – Entradas adicionais do dicionário Document Security Store. ... 132

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 8 -->
<!-- START OF PAGE 9 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
132
Tabela A.4.2 – Entradas adicionais do dicionário VRI
Tabela A.4.3 - Sintaxe ASN.1 por tipos de entradas.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
8

<!-- END OF PAGE 9 -->
<!-- START OF PAGE 10 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
=

# 1 INTRODUÇÃO

1.1 Este documento estabelece os requisitos a serem obrigatoriamente observados pelas entidades criadoras de Políticas de Assinatura Digital no âmbito da Infraestrutura de Chaves Públicas Brasileira - ICP-Brasil, em conformidade com a estrutura proposta pelos padrões ETSI TR 102 272 [1] e ETSI TR 102.038 [2].

1.2 Ele faz parte de um conjunto de normativos criados para regulamentar a geração e verificação de assinaturas digitais no âmbito da ICP-Brasil. Tal conjunto se compõe de:

a) VISÃO GERAL SOBRE ASSINATURAS DIGITAIS NA ICP-BRASIL – DOC- ICP-15 [3];
b) REQUISITOS PARA GERAÇÃO E VERIFICAÇÃO DE ASSINATURAS DIGITAIS NA ICP-BRASIL – DOC- ICP-15.01[4];
c) PERFIL DE USO GERAL PARA ASSINATURAS DIGITAIS NA ICP-BRASIL – DOC- ICP-15.02 [5];
d) REQUISITOS DAS POLÍTICAS DE ASSINATURA NA ICP-BRASIL – DOC-ICP-15.03 (este documento).

1.3 Toda Política de Assinatura elaborada no âmbito da ICP-Brasil DEVE adotar a mesma sintaxe de estrutura empregada neste documento.

1.4 Esta estrutura prevê a criação de uma única assinatura digital (também conhecida como assinatura digital simples ou primária), a criação de assinaturas digitais em paralelo (também conhecidas como coassinaturas), a criação de assinaturas digitais em série (também conhecidas como contra-assinaturas) ou a criação de assinaturas digitais seriais em arquivos PDF (múltiplas assinaturas PAdES).

1.5 As Políticas de Assinatura ICP-Brasil Aprovadas DEVEM ser escritas de uma forma inteligível por seres humanos e; opcionalmente, PODEM ser escritas de uma forma inteligível por sistemas de processamento.

1.6 No caso de políticas que sejam escritas com base no presente documento, a forma inteligível por sistemas de processamento DEVE ser Abstract Syntax Notation. One - ASN.1 ou eXtensible Markup Language - XML.

1.7 As Políticas de Assinatura Aprovadas ICP-Brasil são protegidas contra alterações indevidas por meio da publicação, no repositório da AC Raiz, da Lista de Políticas de Assinatura – LPA contendo o hash das Políticas de Assinatura. A LPA é assinada digitalmente com chave privada associada ao certificado digital do Instituto Nacional de Tecnologia da Informação - ITI. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

1.8 Para facilitar a utilização de políticas de assinatura pelos usuários finais, o ITI criou 14 Políticas de Assinatura-padrão, que estão detalhadas no Anexo 2 deste documento.

1.9 O processo de gerenciamento das Políticas de Assinatura pela AC Raiz da ICP-Brasil está descrito no Anexo 3 deste documento.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 10 -->
<!-- START OF PAGE 11 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

1.10 O restante deste documento está organizado da seguinte forma. O capítulo 2 apresenta o conteúdo de uma Política de Assinatura. O anexo 1 apresenta as tabelas dos atributos disponíveis para cada perfil de política de assinatura. O anexo 2 lista as Políticas de Assinatura Padrão da ICP-Brasil baseadas em CMS Advanced Electronic Signatures (CAdES), em XML Advanced Electronic Signatures (XAdES) e em PDF Advanced Electronic Signatures (PAdES). O anexo 3 descreve o processo de gerenciamento de PAs na ICP-Brasil. O anexo 4 explica as extensões das políticas de assinatura utilizadas no padrão PAdES e as entradas PDF inseridas nos dicionários de validação do PDF.

Nota: Itens não citados nas políticas de assinatura padrão ICP-Brasil serão considerados itens opcionais e, portanto, sua validação e reconhecimento será opcional também. Alguns atributos podem ser proibidos pelo padrão de assinaturas utilizado, portanto recomenda-se a conferência antes da codificação de atributos não citados neste documento.

# 2 CONTEÚDO GERAL DE UMA POLÍTICA DE ASSINATURA

A seguir são apresentados os itens que DEVEM fazer parte de uma Política de Assinatura Aprovada ICP-Brasil, de maneira a permitir que a AC Raiz, ao criar uma PA, tenha informações detalhadas, em conformidade com os documentos ETSI TR 102 272 e ETSI TR 102 038 nos quais os conteúdos são descritos na íntegra.

## 2.1 Identificador da Política de Assinatura (6.1, 8.2)

Neste item DEVE ser informado o identificador (OID) da PA.

## 2.2 Data de Emissão (5, 8.2)

Neste item DEVE ser informada a data em que a PA foi emitida.

## 2.3 Nome da Entidade Emissora da Política de Assinatura (6.1, 8.2)

DEVE ser informado o nome da entidade responsável pela emissão da PA.

## 2.4 Campo de Aplicação (6.1, 8.2)

Neste item DEVE ser definido, em termos gerais, o campo de aplicação da assinatura digital gerada conforme a Política de Assinatura, bem como os propósitos específicos para os quais a assinatura digital é aplicável. Adicionalmente, deverão estar relacionadas, quando cabível, as aplicações para as quais existam restrições ou proibições para o uso da PA.

## 2.5 Política de Validação da Assinatura (6.2, 8.3)

### 2.5.1 Período para Assinatura (6.2, 8.2)

Neste item DEVE ser definido o período de validade (data e hora) inicial e, opcionalmente, final de abrangência das regras definidas na Política de Assinatura aplicáveis às assinaturas digitais que se utilizarem da Política.

### 2.5.2 Regras Comuns (6.3, 8.4)

#### 2.5.2.1 Regras do Signatário e do Verificador (6.5, 8.7)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 11 -->
<!-- START OF PAGE 12 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Nota: item opcional

2.5.2.1.1 Regras do Signatário (6.5.1, 8.7.1)

2.5.2.1.1.1 Dados Externos ou Internos a Assinatura (6.5.1, 8.7.1)

Neste item DEVE ser definido se o conteúdo assinado (documento eletrônico) é externo a assinatura digital. Uma das opções abaixo DEVE ser escolhida:

a) o conteúdo assinado é externo a assinatura; ou
b) o conteúdo assinado é interno a assinatura; ou
c) o conteúdo assinado pode ser tanto externo quanto interno a assinatura.

2.5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios (6.5.1, 8.7.1)

Neste item DEVEM ser relacionados os atributos ou propriedades que DEVEM constar, obrigatoriamente, no pacote da assinatura digital no âmbito desta Política de Assinatura e que são assinados junto ao documento eletrônico. O documento DOC-ICP-15.02 [5], capítulo 2 e 3, define os atributos ou propriedades para os formatos de assinatura digital ICP-Brasil.

2.5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios (6.5.1, 8.7.1)

Neste item DEVEM ser relacionados os atributos ou propriedades que DEVEM constar, obrigatoriamente, no pacote da assinatura digital no âmbito desta Política de Assinatura e que não são assinados junto ao documento eletrônico. O documento DOC-ICP-15.02 [5], capítulo 2 e 3, define os atributos ou propriedades para os formatos de assinatura digital ICP-Brasil.

2.5.2.1.1.4 Referências Obrigatórias de Certificados (6.5.1, 8.7.1)

Neste item DEVE ser definido quais certificados do caminho de certificação do signatário DEVEM ser referenciados nas assinaturas digitais criadas com base nesta Política de Assinatura. Uma das opções abaixo DEVE ser escolhida:

a) o certificado do signatário; ou
b) os certificados do caminho de certificação completo do signatário.

2.5.2.1.1.5 Informações Obrigatórias de Certificados (6.5.1, 8.7.1)

Neste item DEVE ser definido quais certificados do caminho de certificação do signatário devem constar obrigatoriamente nas assinaturas digitais. Uma das opções abaixo DEVE ser escolhida:

a) nenhum certificado; ou
b) o certificado do signatário; ou
c) os certificados do caminho de certificação completo do signatário.

2.5.2.1.1.6 Regras Adicionais do Signatário (6.11, 8.2)

Caso haja a necessidade de incluir regras adicionais relacionadas ao processo de Assinatura Digital executado pelo signatário, essas DEVEM ser incluídas neste item.

2.5.2.1.2 Regras do Verificador (6.5.2, 8.7.2)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 12 -->
<!-- START OF PAGE 13 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

2.5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios (6.5.2, 8.7.2)

Este item DEVE conter os identificadores dos atributos ou propriedades descritos no item 2.5.2.1.1.3, que, caso não incluídos pelo signatário, DEVEM ser adicionados à assinatura pelo verificador.

2.5.2.1.2.2 Regras Adicionais do Verificador (6.11, 8.2)

Caso haja a necessidade de regras adicionais relacionadas ao verificador, essas DEVEM ser incluídas neste item.

2.5.2.2 Condições de Confiabilidade dos Certificados dos Signatários (6.7, 8.8)

Nota: item opcional.

2.5.2.2.1 Requisitos de Certificados (6.7, 8.8.2)

Nota: este item PODE se repetir de acordo com o número de raízes confiáveis.

2.5.2.2.1.1 Raiz Confiável (6.6.1, 8.8.2)

Neste item DEVE constar um certificado autoassinado que deve ser adotado como âncora de confiança no processo de validação do caminho de certificação do signatário.

2.5.2.2.1.2 Restrição do Comprimento do Caminho de Certificação (6.6.1, 8.8.2)

Neste item PODE constar o número máximo de certificados de Autoridade Certificadora (AC) abaixo da âncora de confiança do caminho de certificação do signatário. No caso da ICP-Brasil, este número é, no máximo, 2 (dois).

2.5.2.2.1.3 Conjunto de Políticas de Certificação Aceitáveis (6.6.1, 8.8.2)

Neste item PODEM constar os OIDs das políticas de certificação aceitáveis.

2.5.2.2.1.4 Restrições de Nome (6.6.1, 8.8.2)

Neste item PODEM constar as restrições de nomes aplicáveis.

2.5.2.2.1.5 Restrições de Políticas de Certificação (6.6.1, 8.8.2)

Nota: item opcional.

2.5.2.2.1.5.1 Necessidade da Identificação de Políticas (6.6.1, 8.8.2)

Neste item PODE ser definido a partir de qual nível do caminho de certificação é necessária a identificação das políticas de certificação aceitáveis.

2.5.2.2.1.5.2 Proibição do Mapeamento de Políticas

Neste item PODE ser definido a partir de qual nível do caminho de certificação é proibido o mapeamento de políticas de certificação.

2.5.2.2.2 Requisitos de revogação (6.7, 8.8.3)

2.5.2.2.2.1 Requisitos de Revogação para Certificados Finais (6.6.2, 8.8.3)

2.5.2.2.2.1.1 Mecanismos de Revogação para Certificados (6.6.2, 8.8.3)

Neste item DEVE constar uma das opções de mecanismo de verificação do status de revogação dos certificados:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 13 -->
<!-- START OF PAGE 14 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

a) Lista de Certificados Revogados (LCR); ou
b) Online Certificate Status Protocol (OCSP); ou
c) LCR e OCSP; ou
d) LCR ou OCSP; ou
e) nenhuma verificação; ou
f) outro mecanismo de verificação.

2.5.2.2.2.1.2 Regras Adicionais de Revogação para Certificados (6.1.1, 8.2)

Caso haja a necessidade de regras adicionais para a revogação de certificados, essas devem ser incluídas neste item.

2.5.2.2.2.2 Requisitos de Revogação para Certificados de ACs (6.6.2, 8.8.3)
2.5.2.2.2.2.1 Mecanismos de Revogação para Certificados (6.6.2, 8.8.3)

Neste item DEVE constar uma das opções de mecanismo de verificação do status de revogação dos certificados:

a) LCR; ou
b) OCSP; ou
c) LCR e OCSP; ou
d) LCR ou OCSP; ou
e) nenhuma verificação; ou
f) outro mecanismo de verificação.

2.5.2.2.2.2.2 Regras Adicionais de Revogação para Certificados (6.11, 8.2)

Caso haja a necessidade de regras adicionais para revogação de certificados, essas devem ser incluídas neste item.

2.5.2.3 Condições de Confiabilidade do Carimbo do Tempo (6.11, 8.2)

**Nota:** item opcional.

2.5.2.3.1 Requisitos de Certificados

**Nota:** caso este item não esteja presente, então as regras definidas no item 5.2.2.1 se aplicam aos certificados de Autoridade de Carimbo do Tempo (ACT).

2.5.2.3.1.1 Raiz Confiável (6.6.1, 8.8.2)

Neste item DEVE constar um certificado autoassinado que deve ser adotado como âncora de confiança no processo de validação do caminho de certificação da ACT.

2.5.2.3.1.2 Requisitos de Certificados (6.8, 8.9)

Neste item PODE constar o número máximo de certificados de Autoridade Certificadora (AC) abaixo da ancora de confiança do caminho de certificação do signatário. No caso da ICP-Brasil, este número e, no máximo, 2 (dois).

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 14 -->
<!-- START OF PAGE 15 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

2.5.2.3.1.3 Conjunto de Políticas de Certificação Aceitáveis (6.6.1, 8.8.2)

Neste item PODEM constar os OIDs das políticas de certificação aceitáveis.

2.5.2.3.1.4 Restrições de Nome (6.6.1, 8.8.2)

Neste item PODEM constar as restrições de nomes aplicáveis.

2.5.2.3.1.5 Restrições de Políticas de Certificação (6.6.1, 8.8.2)

Nota: Item OPCIONAL.

2.5.2.3.1.5.1 Necessidade da Identificação de Políticas (6.6.1, 8.8.2)

Neste item PODE ser definido a partir de qual nível do caminho de certificação é necessária a identificação das políticas de certificação aceitáveis.

2.5.2.3.1.5.2 Proibição do Mapeamento de Políticas (6.6.1, 8.8.2)

Neste item PODE ser definido a partir de qual nível do caminho de certificação é proibido o mapeamento de políticas de certificação.

2.5.2.3.2 Requisitos de Revogação (6.8, 8.9)

2.5.2.3.2.1 Requisitos de Revogação para Certificados Finais (6.6.2, 8.8.3)

2.5.2.3.2.1.1 Mecanismos de Revogação para Certificados (6.6.2, 8.8.3)

Neste item DEVE constar uma das opções de mecanismo de verificação do status de revogação dos certificados:

a) LCR; ou
b) OCSP; ou
c) LCR e OCSP; ou
d) LCR ou OCSP; ou
e) nenhuma verificação; ou
f) outro mecanismo de verificação.

2.5.2.3.2.1.2 Regras Adicionais de Revogação para Certificados (6.11, 8.2)

Caso haja a necessidade de regras adicionais à revogação de certificados, essas devem ser incluídas neste item.

2.5.2.3.2.2 Requisitos de Revogação para Certificados de ACs (6.6.2, 8.8.3)

2.5.2.3.2.2.1 Mecanismos de Revogação para Certificados (6.6.2, 8.8.3)

Neste item DEVE constar uma das opções de mecanismo de verificação do status de revogação dos certificados:

a) LCR; ou
b) OCSP; ou
c) LCR e OCSP; ou
d) LCR ou OCSP; ou

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 15 -->
<!-- START OF PAGE 16 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
e) nenhuma verificação; ou
f) outro mecanismo de verificação.

2.5.2.3.2.2.2 Regras Adicionais de Revogação para Certificados (6.11, 8.2)

Caso haja a necessidade de regras adicionais à revogação de certificados, essas devem ser incluídas neste item.

2.5.2.3.3 Restrições de Nome (6.8, 8.9)

Neste item PODEM constar as restrições de nomes aplicáveis.

**Nota:** caso este item não esteja presente, então as regras definidas no item 5.2.3.1.4. se aplicam aos certificados de (ACT).

2.5.2.3.4 Período de Cautela (6.8, 8.9)

Neste item PODE constar o período de tempo, após o instante da assinatura, que o verificador deve aguardar antes de obter o status de revogação necessário para validar a chave do signatário.

2.5.2.3.5 Atraso do Carimbo do Tempo (6.8, 8.9)

Neste item pode constar o período máximo de tempo aceitável entre o instante informado pelo carimbo do tempo e o instante da assinatura.

2.5.2.4 Condições de Confiabilidade dos Atributos (6.9, 8.10)

**Nota:** item OPCIONAL.

2.5.2.5 Conjunto de Restrições de Algoritmos (6.10, 8.11)

**Nota:** na necessidade de se incluir um conjunto de restrições de algoritmos, esses DEVEM ser escolhidos entre os listados no documento Padrões e Algoritmos Criptográficos da ICP-Brasil - DOC-ICP-01.01 [6].

2.5.2.5.1 Restrições de Algoritmos para Signatários (6.10, 8.11)

**Nota:** item OPCIONAL.

2.5.2.5.1.1 Restrições de Algoritmos (6.10, 8.11)

**Nota:** este item PODE se repetir de acordo com o número de restrições de algoritmos necessárias.

2.5.2.5.1.1.1 Identificador de Algoritmo (6.10, 8.11)

Neste item DEVE constar o OID do algoritmo a ser restringido.

2.5.2.5.1.1.2 Tamanho Mínimo de Chaves (6.10, 8.11)

Neste item PODE constar o tamanho mínimo de chave em bits.

2.5.2.5.1.1.3 Regras Adicionais de Restrições (6.11, 8.2)

Caso haja a necessidade de regras adicionais a restrições de algoritmos, essas devem ser incluídas neste item.

2.5.2.5.2 Restrições de Algoritmos para AC Final (6.10, 8.11)

**Nota:** item OPCIONAL.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
15

<!-- END OF PAGE 16 -->
<!-- START OF PAGE 17 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

2.5.2.5.2.1 Restrições de Algoritmos (6.10, 8.11)

Nota: este item PODE se repetir de acordo com o número de restrições de algoritmos necessárias.

2.5.2.5.2.1.1 Identificador de Algoritmo (6.10, 8.11)

Neste item DEVE constar o OID do algoritmo a ser restringido.

2.5.2.5.2.1.2 Tamanho Mínimo de Chaves (6.10, 8.11)

Neste item PODE constar o tamanho mínimo de chave em bits.

2.5.2.5.2.1.3 Regras Adicionais de Restrições (6.11, 8.2)

Caso haja a necessidade de regras adicionais a restrições de algoritmos, essas devem ser incluídas neste item.

2.5.2.5.3 Restrições de Algoritmos para AC Intermediária (6.10, 8.11)

Nota: item OPCIONAL.

2.5.2.5.3.1 Restrições de Algoritmos (6.10, 8.11)

Nota: este item PODE se repetir de acordo com o número de restrições necessárias.

2.5.2.5.3.1.1 Identificador de Algoritmo (6.10, 8.11)

Neste item DEVE constar o OID do algoritmo a ser restringido.

2.5.2.5.3.1.2 Tamanho Mínimo de Chaves (6.10, 8.11)

Neste item PODE constar o tamanho mínimo de chave em bits.

2.5.2.5.3.1.3 Regras Adicionais de Restrições (6.11, 8.2)

Caso haja a necessidade de regras adicionais a restrições de algoritmos, essas devem ser incluídas neste item.

2.5.2.5.4 Restrições de Algoritmos para Autoridades de Atributo (6.10, 8.11)

Nota: item OPCIONAL.

2.5.2.5.5 Restrições de Algoritmos para Autoridades de Carimbo do Tempo (6.10, 8.11)

Nota: item OPCIONAL.

2.5.2.5.5.1 Restrições de Algoritmos (6.10, 8.11)

Nota: este item PODE se repetir de acordo com o número de restrições de algoritmos necessárias.

2.5.2.5.5.1.1 Identificador de Algoritmo (6.10, 8.11)

Neste item DEVE constar o OID do algoritmo a ser restringido.

2.5.2.5.5.1.2 Tamanho Mínimo de Chaves (6.10, 8.11)

Neste item PODE constar o tamanho mínimo de chave em bits.

2.5.2.5.5.1.3 Regras Adicionais de Restrições (6.11, 8.2)

Caso haja a necessidade de regras adicionais a restrições de algoritmos, essas devem ser incluídas neste item.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
16

<!-- END OF PAGE 17 -->
<!-- START OF PAGE 18 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

2.5.2.6 Regras Adicionais (6.11, 8.2)

Caso haja a necessidade de incluir regras adicionais para geração ou verificação de assinaturas digitais, essas DEVEM ser incluídas neste item.

2.5.3 Informações Adicionais sobre a Validação das Assinaturas (6.11, 8.2)

Caso haja a necessidade de informações adicionais quanto à validação das assinaturas digitais no âmbito desta Política de Assinatura, elas DEVEM ser incluídas neste item.

2.6 Informações Adicionais sobre a Política de Assinatura (6.11, 8.2)

Caso haja a necessidade de informações adicionais sobre a Política de Assinatura, elas DEVEM estar incluídas neste item.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
17

<!-- END OF PAGE 18 -->
<!-- START OF PAGE 19 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 3 DOCUMENTOS ICP-BRASIL REFERENCIADOS

3.1 Os documentos abaixo são aprovados por Resoluções do Comitê Gestor da ICP-Brasil, podendo ser alterados, quando necessário, pelo mesmo tipo de dispositivo legal. O sítio http://www.iti.gov.br publica a versão mais atualizada desses documentos e as resoluções que os aprovaram.

|  REF. | NOME DO DOCUMENTO | CÓDIGO  |
| --- | --- | --- |
|  [3] | VISÃO GERAL SOBRE ASSINATURAS DIGITAIS NA ICP-BRASIL
Aprovado pela Resolução nº 62, de 09 de janeiro de 2009 | DOC-ICP-15  |
|  [7] | REQUISITOS MÍNIMOS PARA AS POLÍTICAS DE CERTIFICADO NA ICP-BRASIL
Aprovado pela Resolução nº 07, de 12 de dezembro de 2001 | DOC-ICP-04  |

3.2 Os documentos abaixo são aprovados por Instrução Normativa da AC Raiz, podendo ser alterados, quando necessário, pelo mesmo tipo de dispositivo legal. O sítio http://www.iti.gov.br publica a versão mais atualizada desses documentos e as instruções normativas que os aprovaram.

|  REF. | NOME DO DOCUMENTO | CÓDIGO  |
| --- | --- | --- |
|  [4] | REQUISITOS PARA GERAÇÃO E VERIFICAÇÃO DE ASSINATURAS DIGITAIS NA ICP-BRASIL
Aprovado pela Instrução Normativa nº 01, de 09 de janeiro de 2009 | DOC-ICP-15.01  |
|  [5] | PERFIL DE USO GERAL PARA ASSINATURAS DIGITAIS NA ICP-BRASIL
Aprovado pela Instrução Normativa nº 02, de 09 de janeiro de 2009 | DOC-ICP-15.02  |
|  [6] | PADRÕES E ALGORITMOS CRIPTOGRÁFICOS DA ICP-BRASIL
Aprovado pela Instrução Normativa nº 04, de 18 de maio de 2006 | DOC-ICP-01.01  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 19 -->
<!-- START OF PAGE 20 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
4 BIBLIOGRAFIA

[1] ETSI. ASN.1 Format for Signature Policies. Number TR 102 272. v.1.1.1, dez. 2003.
[2] ETSI. XML Format for Signature Policies. Number TR 102 038. v.1.1.1, abr. 2002.
[8] ETSI. Electronic Signatures and Infrastructures; PDF Advanced Electronic Signature Profiles; Part 3: PAdES Enhanced - PAdES-BES and PAdES-EPES Profiles. TS 102 778-3. V1.2.1. 2010.
[9] ETSI. Electronic Signatures and Infrastructures; PDF Advanced Electronic Signature Profiles; Part 4: PAdES Long Term - PAdES-LTV Profile. TS 102 778-4. V1.1.1. 2009.
[10] RFC 3370, IETF. Cryptographic Message Syntax (CMS) Algorithms, Aug. 2002.
[11] RFC 5754, IETF. Using SHA2 Algorithms with Cryptographic Message Syntax. Jan, 2010.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
19

<!-- END OF PAGE 20 -->
<!-- START OF PAGE 21 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# ANEXO 1

# 1 POLÍTICAS DE ASSINATURA-PADRÃO ICP-BRASIL

Para facilitar a utilização de Políticas de Assinatura pelos usuários finais, foram criadas 14 políticas de assinatura, as quais estão descritas no Anexo II deste documento. Essas políticas foram criadas a partir do cruzamento do Perfil de Uso Geral para Assinaturas Digitais ICP-Brasil, definido no documento DOC-ICP-15.02 [5], com os cinco formatos de assinatura digital da ICP-Brasil, derivados dos padrões CMS Advanced Electronic Signature (CAdES), XML Advanced Electronic Signature (XAdES) e PDF Advanced Electronic Signature (PAdES), citados no documento DOC-ICP-15.01 [4], a saber:

a) Assinatura Digital com Referência do Tempo (AD-RT);
b) Assinatura Digital com Referência Básica (AD-RB);
c) Assinatura Digital com Referências para Validação (AD-RV);
d) Assinatura Digital com Referências Completas (AD-RC);
e) Assinatura Digital com Referências para Arquivamento (AD-RA).

As Tabelas A.2 a A.13 mostram a combinação dos elementos aplicada aos diferentes contextos de assinatura. A Tabela A.1 mostra o significado das abreviações utilizadas nas tabelas seguintes.

Tabela A.1: Abreviações utilizadas.

|  Abreviação | Significado  |
| --- | --- |
|  ND | Não deve (proibido)  |
|  O | Obrigatório  |
|  P | Pode (opcional)  |
|  R | Recomendável  |

Nota 1: Na codificação do atributo "SignaturePolicyIdentifier" (id-aa-ets-sigPolicyId {1.2.840.113549.1.9.16.2.15}), recomenda-se o uso do campo "sigPolicyQualifiers" para a indicação da Política de Assinatura, em Linguagem de Máquina, empregada nesta assinatura. Quando utilizado, o campo "sigPolicyQualifiers" somente deverá conter um único qualificador do tipo "spuri" (id-spq-ets-uri {1.2.840.113549.1.9.16.5.1}), cujo conteúdo deverá ser uma URI, ou URL, apontando para a Política de Assinatura, em Linguagem de Máquina, usada na assinatura.

Nota 2: O hash da política de assinatura no atributo id-aa-ets-sigPolicyId da assinatura deve ser o hash interno que está na própria PA e não o hash da PA que se encontra publicada na LPA.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 21 -->
<!-- START OF PAGE 22 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Nota 3: Em atenção à RFC 3370 (Cryptographic Message Syntax (CMS) Algorithms), item "2.1 SHA-1" [10]; e RFC 5754 (Using SHA2 Algorithms with Cryptographic Message Syntax), item "2 - Message Digest Algorithms" [11], recomenda-se a ausência do campo "parameters" na estrutura "AlgorithmIdentifier", usada na indicação do algoritmo de hash, presente nas estruturas ASN.1 "SignedData.digestAlgorithms", "SignerInfo.digestAlgorithm" e "SignaturePolicyId.sigPolicyHash.hashAlgorithm".

$$
AlgorithmIdentifier ::= SEQUENCE {
algorithm OBJECT IDENTIFIER,
parameters ANY DEFINED BY algorithm OPTIONAL
}
$$

Nota 4: Para o atributo ESSCertIDv2, utilizado nas versões 2.1 das políticas de assinatura baseadas em CAdES, as aplicações NÃO DEVEM codificar o campo "hashAlgorithm" caso utilizem o mesmo algoritmo definido como valor default (SHA-256), conforme ISO 8825-1.

Nota 5: Quando do uso da codificação MIME no campo eContent, alerta-se para a necessidade de cuidado com a conversão do arquivo (attached/detached), pois esta conversão poderá invalidar a assinatura digital.

Nota 6: Recomenda-se o uso do MimeType caso seja codificada a propriedade DataObjectFormat, para as políticas XAdES.

Nota 7: Para as políticas PAdES deve-se observar as restrições de uso de atributos impostas nas Tabelas A.14 à A.21. Essas restrições são baseadas nos perfis ETSI PAdES-EPES [8] e ETSI PAdES-LTV [9].

Nota 8: Nas assinaturas PAdES-ICP-Brasil, deve-se usar as extensões de dicionários condizentes com as estruturas PDF para que uma aplicação leitora aderente reconheça e seja capaz de validar corretamente as assinaturas. Para todas as assinaturas deve-se usar as extensões indicadas no item sobre extensões do DOC-ICP 15.02 [5].

Nota 9: As tabelas A.14 à A.21 definem os atributos do CMS, contidos na entrada Contents do dicionário de assinatura, assim como as entradas dos dicionários de assinatura, DSS, VRI e Document Time-stamp.

Nota 10: Quando o atributo Id-aa-signingCertificate ou Id-aa-signingCertificateV2, de um carimbo do tempo, tiver mais de uma referência, então deve-se aplicar a seguinte regra para aceitar ou não o carimbo em questão:

- Para cada referência extra, além da primeira, identificá-la e:
- se a referência for um certificado de chave pública:
- aceitar e incluir essa referência na lista de certificados que limitam a validação do caminho de certificação.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 22 -->
<!-- START OF PAGE 23 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

- se a referência for um alvará (ver item sobre visualização e/ou extração do conteúdo digital, do DOC-ICP 15.01 [4]):
- aceitar e incluir na lista de alvarás a serem verificados.
- se a referência não for identificada:
- gerar um alerta indicando que o carimbo possui uma referência dentro do atributo Id-aa-signingCertificate ou Id-aa-signingCertificateV2 que é desconhecida e o verificador só deve aceitar esse carimbo caso confie no autor. Caso contrário deve-se descartar tal artefato.

Nota 11: Nas assinaturas PAdES-ICP-Brasil o único atributo não-assinado permitido é o id-aa-signatureTimeStampToken. Já para o atributo id-aa-signatureTimeStampToken não é permitido nenhum atributo não assinado. Isto ocorre pela natureza da estrutura de dados das assinaturas PAdES, que possuem um tamanho pré-definido e registrado na entrada ByteRange, do dicionário de assinaturas. Toda informação adicional que um atributo não-assinado proporciona é substituída pelo conteúdo do dicionário DSS.

Tabela A.2: Atributos assinados no SignerInfo do Assinante

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Tipo de conteúdo
(content type) | id-contentType | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Resumo criptográfico da mensagem
(message digest) | id-messageDigest | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Certificado do signatário
(ESS signing certificate) | Id-aa-signingCertificate^{1}
id-aa-signingCertificateV2^{2} | O | O | O | O | O  |
|   |  SigningCertificate  |   |   |   |   |   |
|  Identificador da política de assinatura
(signature policy identifier) | id-aa-ets-sigPolicyId | O | O | O | O | O  |
|   |  SignaturePolicyIdentifier  |   |   |   |   |   |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 23 -->
<!-- START OF PAGE 24 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.3: Presença de atributos não-assinados no SignerInfo do signatário

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Carimbo do tempo de assinatura
(signature time stamp) | id-aa-signatureTimeStampToken | P | O | O | O | P  |
|   |  SignatureTimeStamp  |   |   |   |   |   |
|  Referências completas aos certificados
(complete certificate references) | id-aa-ets-certificateRefs | P | P | O | O | O  |
|   |  CompleteCertificateRefs  |   |   |   |   |   |
|  Referências completas à revogação
(complete revogation references) | id-aa-ets-revocationRefs | P | P | O | O | O  |
|   |  CompleteRevocationRefs  |   |   |   |   |   |
|  Carimbo do tempo das referências
(time-stamped certificate crls references) | id-aa-ets-escTimeStamp | P | P | O | O | P  |
|   |  SigAndRefsTimesStamp  |   |   |   |   |   |
|  Valores dos certificados
(certificate values) | id-aa-ets-certValues | P | P | P | O | O  |
|   |  CertificateValues  |   |   |   |   |   |
|  Valores de revogação
(revocation values) | id-aa-ets-revocationValues | P | P | P | O | O  |
|   |  RevocationValues  |   |   |   |   |   |
|  Carimbo do tempo de arquivamento
(archive time-stamp) | id-aa-ets-archiveTimestampV2 | P | P | P | P | O  |
|   |  ArchiveTimeStamp  |   |   |   |   |   |

Nota: Contra-assinaturas NÃO DEVEM ser empregadas após a aposição de qualquer carimbo do tempo de arquivamento, devido à interferência no processo de validação.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 24 -->
<!-- START OF PAGE 25 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.4: Presença de atributos assinados no SignerInfo de “contra assinatura”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Resumo criptográfico da mensagem (message digest) | id-messageDigest | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Certificado do signatário v1 (ESS signing certificate) | id-aa-signingCertificate | O | O | O | O | O  |
|   |  SigningCertificate  |   |   |   |   |   |
|  Identificador da política de assinatura (signature policy identifier) | id-aa-ets-sigPolicyId | ND | ND | ND | ND | ND  |
|   |  SignaturePolicyIdentifier  |   |   |   |   |   |

Nota: Contra-assinaturas não devem receber o atributo de identificação da política de assinatura, pois elas seguem as regras da política de assinatura da assinatura que as contém.

Tabela A.5: Presença de atributos não-assinados no SignerInfo de “contra assinatura”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | CT | RV | RC | RA  |
|  Carimbo do tempo de assinatura (signature time stamp) | id-aa-signatureTimeStampToken | P | O | O | O | P  |
|   |  SignatureTimeStamp  |   |   |   |   |   |
|  Referências completas aos certificados (complete certificate references) | id-aa-ets-certificateRefs | P | P | O | O | O  |
|   |  CompleteCertificateRefs  |   |   |   |   |   |
|  Referências completas à revogação (complete revogation references) | id-aa-ets-revocationRefs | P | P | O | O | O  |
|   |  CompleteRevocationRefs  |   |   |   |   |   |
|  Carimbo do tempo das referências (time-stamped certificate crls references) | id-aa-ets-escTimeStamp | P | P | O | O | P  |
|   |  SigAndRefsTimesStamp  |   |   |   |   |   |
|  Valores dos certificados (certificate values) | id-aa-ets-certValues | P | P | P | O | O  |
|   |  CertificateValues  |   |   |   |   |   |
|  Valores de revogação (revocation values) | id-aa-ets-revocationValues | P | P | P | O | O  |
|   |  RevocationValues  |   |   |   |   |   |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 25 -->
<!-- START OF PAGE 26 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.6: Presença de atributos assinados no TimeStampToken de “carimbo do tempo de conteúdo”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Tipo de conteúdo (content type) | id-contentType | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Resumo criptográfico da mensagem (message digest) | id-messageDigest | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Certificado do signatário (ESS signing certificate) | Id-aa-signingCertificate 1,3
id-aa-signingCertificateV2 2 3 | O | O | O | O | O  |
|   |  SigningCertificate  |   |   |   |   |   |

Tabela A.7: Presença de atributos não-assinados no TimeStampToken de “carimbo do tempo de conteúdo”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Referências completas aos certificados
(complete certificate references) | id-aa-ets-certificateRefs | R | R | O | O | O  |
|   |  CompleteCertificateRefs  |   |   |   |   |   |
|  Referências completas à revogação
(complete revogation references) | id-aa-ets-revocationRefs | R | R | O | O | O  |
|   |  CompleteRevocationRefs  |   |   |   |   |   |
|  Valores dos certificados
(certificate values) | id-aa-ets-certValues | R | R | R | O | O  |
|   |  CertificateValues  |   |   |   |   |   |
|  Valores de revogação
(revocation values) | id-aa-ets-revocationValues | R | R | R | O | O  |
|   |  RevocationValues  |   |   |   |   |   |

Nota: Como o atributo “carimbo do tempo de conteúdo” é assinado, antes da assinatura do signatário devem ser incluídos os atributos não-assinados necessários para o perfil de AD mais complexo considerando seu ciclo de vida completo, pois não poderão ser incluídos posteriormente.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 26 -->
<!-- START OF PAGE 27 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.8: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura”.

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Tipo de conteúdo (content type) | id-contentType | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Resumo criptográfico da mensagem (message digest) | id-messageDigest | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Certificado do signatário (ESS signing certificate) | Id-aa-signingCertificate 1 3 | O | O | O | O | O  |
|   |  id-aa-signingCertificateV2 2 3  |   |   |   |   |   |
|   |  SigningCertificate  |   |   |   |   |   |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 27 -->
<!-- START OF PAGE 28 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.9: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura.”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Referências completas aos certificados
(complete certificate references) | id-aa-ets-certificateRefs | P | P | O¹ | O¹ | O¹  |
|   |  CompleteCertificateRefs  |   |   |   |   |   |
|  Referências completas à revogação
(complete revogation references) | id-aa-ets-revocationRefs | P | P | O¹ | O¹ | O¹  |
|   |  CompleteRevocationRefs  |   |   |   |   |   |
|  Valores dos certificados
(certificate values) | id-aa-ets-certValues | P | P | P | O¹ | O¹  |
|   |  CertificateValues  |   |   |   |   |   |
|  Valores de revogação
(revocation values) | id-aa-ets-revocationValues | P | P | P | O¹ | O¹  |
|   |  RevocationValues  |   |   |   |   |   |

Nota: A inclusão ou atualização destas propriedades é obrigatória no momento que antecede a inclusão do carimbo do tempo das referências. Caso o carimbo do tempo das referências ainda não tenha sido aplicado, a presença destas propriedades é opcional.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 28 -->
<!-- START OF PAGE 29 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.10: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo das referências”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Tipo de conteúdo (content type) | id-contentType | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Resumo criptográfico da mensagem (message digest) | id-messageDigest | O | O | O | O | O  |
|   |  |   |   |   |   |   |
|  Certificado do signatário (ESS signing certificate) | Id-aa-signingCertificate 1 3
id-aa-signingCertificateV2 2 3 | O | O | O | O | O  |
|   |  SigningCertificate  |   |   |   |   |   |

1. Atributo a ser adotado para as versões 1.0, 1.1 e 2.0;
2. Atributo a ser adotado a partir da versão 2.1.
3. Além do certificado do assinante e dos certificados do caminho de certificação, admite-se a inclusão da referência ao alvará do carimbo do tempo de forma opcional. Caso o alvará seja referenciado, então é obrigatória a inclusão do próprio alvará dentro do campo certificates do SignedData do carimbo do tempo.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 29 -->
<!-- START OF PAGE 30 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.11: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo das referências”

|  Nome do atributo / Propriedade | Identificação do atributo | Perfil AD  |   |   |   |   |
| --- | --- | --- | --- | --- | --- | --- |
|   |  Propriedade | RB | RT | RV | RC | RA  |
|  Referências completas aos certificados
(complete certificate references) | id-aa-ets-certificateRefs | P | P | O¹ | O¹ | O¹  |
|   |  CompleteCertificateRefs  |   |   |   |   |   |
|  Referências completas à revogação
(complete revogation references) | id-aa-ets-revocationRefs | P | P | O¹ | O¹ | O¹  |
|   |  CompleteRevocationRefs  |   |   |   |   |   |
|  Valores dos certificados
(certificate values) | id-aa-ets-certValues | P | P | P | O¹ | O¹  |
|   |  CertificateValues  |   |   |   |   |   |
|  Valores de revogação
(revocation values) | id-aa-ets-revocationValues | P | P | P | O¹ | O¹  |
|   |  RevocationValues  |   |   |   |   |   |

Nota: A inclusão ou atualização destas propriedades é obrigatória no momento que antecede a inclusão do carimbo do tempo de arquivamento. Caso o tipo de assinatura não exija carimbo do tempo de arquivamento ou este ainda não tenha sido aplicado, a presença destas propriedades é opcional.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 30 -->
<!-- START OF PAGE 31 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.12: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo de arquivamento”

|  Nome do atributo / Propriedade | Identificação do atributo | Carimbo  |   |
| --- | --- | --- | --- |
|   |  Propriedade | Anterior | Corrente  |
|  Tipo de conteúdo
(content type) | id-contentType | O | O  |
|   |  |   |   |
|  Resumo criptográfico da mensagem
(message digest) | id-messageDigest | O | O  |
|   |  |   |   |
|  Certificado do signatário
(ESS signing certificate) | Id-aa-signingCertificate 1 3
id-aa-signingCertificateV2 2 3 | O | O  |
|   |  SigningCertificate  |   |   |

Tabela A.13: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo de arquivamento”

|  Nome do atributo / Propriedade | Identificação do atributo | Carimbo  |   |
| --- | --- | --- | --- |
|   |  Propriedade | Anterior | Corrente  |
|  Referências completas aos certificados
(complete certificate references) | id-aa-ets-certificateRefs | O | P  |
|   |  CompleteCertificateRefs  |   |   |
|  Referências completas à revogação
(complete revogation references) | id-aa-ets-revocationRefs | O | P  |
|   |  CompleteRevocationRefs  |   |   |
|  Valores dos certificados
(certificate values) | id-aa-ets-certValues | O | P  |
|   |  CertificateValues  |   |   |
|  Valores de revogação
(revocation values) | id-aa-ets-revocationValues | O | P  |
|   |  RevocationValues  |   |   |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 31 -->
<!-- START OF PAGE 32 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.14: Atributos assinados no SignerInfo do Assinante para assinaturas PAdES

|  Nome do Atributo | Identificação do Atributo | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Tipo de conteúdo (content type) | id-contentType | O | O | O | O  |
|  Resumo criptográfico da mensagem (message digest) | id-messageDigest | O | O | O | O  |
|  Certificado do signatário (ESS signing certificate) | Id-aa-signingCertificate | ND | ND | ND | ND  |
|   |  Id-aa-signingCertificate V2 | O | O | O | O  |
|  Identificador da política de assinatura (signature policy identifier) | id-aa-ets-sigPolicyId | O | O | O | O  |
|  Atributos do signatário (signer attributes) | id-aa-ets-signerAttr | P | P | P | P  |
|  Instante da assinatura (signing time) | id-signingTime | ND | ND | ND | ND  |
|  Localização do signatário (signer location) | id-aa-ets-signerLocation | ND | ND | ND | ND  |
|  Carimbo do tempo de conteúdo (content time stamp) | id-aa-ets-contentTimeStamp | P | P | P | P  |
|  Informações de Revogação (adbe Revocation Information) | adbe-revocationInfoArchival | ND | ND | ND | ND  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 32 -->
<!-- START OF PAGE 33 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.15: Presença de atributos não-assinados no SignerInfo do signatário para assinatura PAdES
(A tabela A.15 foi descontinuada pela Instrução Normativa 08/2018)

|  Nome do Atributo | Identificação do Atributo | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Contra assinatura (countersignature) | id-countersignature | ND | ND | ND | ND  |
|  Carimbo do tempo de assinatura (signature time-stamp) | id-aa-signatureTimeStampToken | P | O | O | O  |
|  Referências completas aos certificados (complete certificate references) | id-aa-ets-certificateRefs | ND | ND | ND | ND  |
|  Referências completas à revogação (complete revogation references) | id-aa-ets-revocationRefs | ND | ND | ND | ND  |
|  Referências aos certificados de atributo (attribute certificate references) | id-aa-ets-attrCertificateRefs | ND | ND | ND | ND  |
|  Referências à revogação de atributo (attribute revogation references) | id-aa-ets-attrRevocationRefs | ND | ND | ND | ND  |
|  Carimbo do tempo das referências (time-stamped certificate erls references) | id-aa-ets-escTimeStamp | ND | ND | ND | ND  |
|  Valores dos certificados (certificate values) | id-aa-ets-certValues | ND | ND | ND | ND  |
|  Valores de revogação (revocation values) | id-aa-ets-revocationValues | ND | ND | ND | ND  |
|  Carimbo do tempo de arquivamento (archive time-stamp) | id-aa-ets-archiveTimestampV2 | ND | ND | ND | ND  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 33 -->
<!-- START OF PAGE 34 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.16: Presença de atributos assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura” para assinaturas PAdES.

|  Nome do Atributo | Identificação do Atributo | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Tipo de conteúdo (content type) | id-contentType | O | O | O | O  |
|  Resumo criptográfico da mensagem (message digest) | id-messageDigest | O | O | O | O  |
|  Certificado do signatário (ESS signing certificate) | Id-aa-signingCertificate¹ | ND | ND | ND | ND  |
|   |  Id-aa-signingCertificateV2¹ | O | O | O | O  |
|  Identificador da política de assinatura (signature policy identifier) | id-aa-ets-sigPolicyId | ND | ND | ND | ND  |
|  Atributos do signatário (signer attributes) | id-aa-ets-signerAttr | ND | ND | ND | ND  |
|  Instante da assinatura (signing time) | id-signingTime | ND | ND | ND | ND  |
|  Localização do signatário (signer location) | id-aa-ets-signerLocation | ND | ND | ND | ND  |
|  Carimbo do tempo de conteúdo (content time stamp) | id-aa-ets-contentTimeStamp | ND | ND | ND | ND  |

¹ Além do certificado do assinante e dos certificados do caminho de certificação, admite-se a inclusão da referência ao alvará do carimbo do tempo de forma opcional. Caso o alvará seja referenciado, então é obrigatória a inclusão do próprio alvará dentro do campo certificates do SignedData do carimbo do tempo.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 34 -->
<!-- START OF PAGE 35 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

—

(A tabela A.17: Presença de atributos não-assinados no SignerInfo do TimeStampToken de “carimbo do tempo de assinatura” para assinaturas PAdES.

(A tabela A.17 foi descontinuada pela Instrução Normativa 08/2018)

|  Nome do Atributo | Identificação do Atributo | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Contra assinatura
(countersignature) | id-countersignature | ND | ND | ND | ND  |
|  Carimbo do tempo de assinatura
(signature time-stamp) | id-aa-signatureTimeStampToken | ND | ND | ND | ND  |
|  Referências completas aos certificados
(complete certificate references) | id-aa-ets-certificateRefs | ND | ND | ND | ND  |
|  Referências completas à revogação
(complete revogation references) | id-aa-ets-revocationRefs | ND | ND | ND | ND  |
|  Referências aos certificados de atributo
(attribute certificate references) | id-aa-ets-attrCertificateRefs | ND | ND | ND | ND  |
|  Referências à revogação de atributo
(attribute revogation references) | id-aa-ets-attrRevocationRefs | ND | ND | ND | ND  |
|  Carimbo do tempo das referências
(time-stamped certificate erls references) | id-aa-ets-escTimeStamp | ND | ND | ND | ND  |
|  Valores dos certificados
(certificate values) | id-aa-ets-certValues | ND | ND | ND | ND  |
|  Valores de revogação
(revocation values) | id-aa-ets-revocationValues | ND | ND | ND | ND  |
|  Carimbo do tempo de arquivamento
(archive time-stamp) | id-aa-ets-archiveTimestampV2 | ND | ND | ND | ND  |

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 35 -->
<!-- START OF PAGE 36 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.18: Presença das entradas do dicionário de assinaturas do PAdES.

|  Entrada | Valor padrão | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Type | Sig | O | O | O | O  |
|  Filter | PBAD_PAdES | O | O | O | O  |
|  SubFilter | PBAD.PAdES | O | O | O | O  |
|  Contents | Não aplicável | O | O | O | O  |
|  Cert | Não aplicável | ND | ND | ND | ND  |
|  ByteRange | Não aplicável | O | O | O | O  |
|  Reference | Não aplicável | P | P | P | P  |
|  Changes | Não aplicável | P | P | P | P  |
|  Name | Não aplicável | P | P | P | P  |
|  M | Não aplicável | P | P | P | P  |
|  Location | Não aplicável | P | P | P | P  |
|  Reason | Não aplicável | P | P | P | P  |
|  ContactInfo | Não aplicável | P | P | P | P  |
|  R | Não aplicável | ND | ND | ND | ND  |
|  V | 0 | P | P | P | P  |
|  Prop_Build | Não aplicável | P | P | P | P  |
|  Prop_AuthTime | Não aplicável | P | P | P | P  |
|  Prop_AuthType | Não aplicável | ND | ND | ND | ND  |

Nota: É possível associar um Seed Value Dictionary a um dicionário de assinatura, esse dicionário pode ser usado para indicar qual política de assinatura um assinante deverá usar. Para isso, devem ser usadas as modificações descritas no documento ETSI TS 102 778-3. É importante perceber que o uso desse dicionário não substitui o uso de políticas de assinatura, pois esse dicionário é apenas uma condição para a geração da assinatura, enquanto uma PA são regras acordadas entre assinante e verificador as quais ambos devem seguir.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 36 -->
<!-- START OF PAGE 37 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.19: Presença das entradas do dicionário DSS do PAdES.

|  Entrada | Valor Padrão | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Type | DSS | O | O | O | O  |
|  VRI | Não aplicável | O | O | O | O  |
|  Certs | Não aplicável | O | O | O | O  |
|  OCSPs | Não aplicável | P* | P* | P* | P*  |
|  CRLs | Não aplicável | P* | P* | P* | P*  |
|  PBAD_PolicyArtifacts | Não aplicável | P | P | P | O  |
|  PBAD_LpaArtifacts | Não aplicável | P | P | P | O  |
|  PBAD_LpaSignatures | Não aplicável | P | P | P | O  |

Nota: As entradas OCSPs e CRLs DEVEM constar no DSS. Nota-se que o uso de ambas ao mesmo tempo não é proibido.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 37 -->
<!-- START OF PAGE 38 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.20: Presença das entradas do dicionário VRI do PAdES.

|  Entrada | Valor Padrão | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Type | VRI | O | O | O | O  |
|  Cert | Não aplicável | O | O | O | O  |
|  OCSP | Não aplicável | P¹ | P¹ | P¹ | P¹  |
|  CRL | Não aplicável | P¹ | P¹ | P¹ | P¹  |
|  TU | Não aplicável | P² | P² | P² | P²  |
|  TS | Não aplicável | P² | P² | P² | P²  |
|  PBAD_PolicyArtifact | Não aplicável | P | P | P | O  |
|  PBAD_LpaArtifact | Não aplicável | P | P | P | O  |
|  PBAD_LpaSignature | Não aplicável | P | P | P | O  |

Nota 1: As entradas OCSP ou CRL DEVEM constar no VRI, devendo ser observado o disposto no item 2.5 do anexo 4 deste documento. Nota-se que o uso de ambas ao mesmo tempo não é proibido.

Nota 2: As entradas TU e TS são mutuamente exclusivas, ou seja, se um for codificado o outro não deve ser codificado.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 38 -->
<!-- START OF PAGE 39 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Tabela A.21: Presença das entradas do dicionário de assinatura do Document Timestamp do PAdES.

|  Entrada | Valor Padrão | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |   |  RB | RT | RC | RA  |
|  Type | DocTimeStamp | O | O | O | O  |
|  SubFilter | ETSI.RFC3161 | O | O | O | O  |
|  Contents | Não aplicável | O | O | O | O  |
|  V | 0 | P | P | P | P  |

Tabela A.22: Presença de dicionários PDF relacionados às assinaturas PAdES.

|  Dicionário | Identificação do Dicionário | Perfil AD  |   |   |   |
| --- | --- | --- | --- | --- | --- |
|   |  | RB | RT | RC | RA  |
|  Dicionário de assinatura | Signature Dictionary | O | O | O | O  |
|  DSS | DSS Dictionary | P | P | O | O  |
|  VRI | VRI Dictionary | P* | P* | O | O  |
|  Document Time-stamp | Document Time-stamp Dictionary | P | P | O | O  |

Nota: Caso seja utilizado DSS para os formatos RB e RT, deve-se usar o VRI.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 39 -->
<!-- START OF PAGE 40 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

ANEXO 2

# 1 POLÍTICA-PADRÃO AD-RB BASEADA EM CADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.1.1.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO CMS, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.4. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 2.0: 26/12/2011;
d) para a versão 2.1: 06/03/2012;
e) para a versão 2.2: 27/04/2016;
f) para a versão 2.3: 14/05/2018; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 40 -->
<!-- START OF PAGE 41 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

g) para a versão 2.4: 12/06/2025. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

# 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name “C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informação – ITI”.

# 4 Campo de Aplicação

Este tipo de assinatura deve ser utilizado em aplicações ou processos de negócio nos quais a assinatura digital agrega segurança à autenticação de entidades e verificação de integridade, permitindo sua validação durante o prazo de validade dos certificados dos signatários.

Uma vez que não são usados carimbos do tempo, a validação posterior só será possível se existirem referências temporais que identifiquem o momento em que ocorreu a assinatura digital. Nessas situações, deve existir legislação específica ou um acordo prévio entre as partes definindo as referências a serem utilizadas.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 29/02/2012.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 06/03/2012 a 02/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.3, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos assinados:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 41 -->
<!-- START OF PAGE 42 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

a) id-contentType;
b) id-messageDigest;
c.1) Para as versões 1.0, 1.1 e 2.0, id-aa-signingCertificate;
c.2) A partir da versão 2.1, inclusive, id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

## 5.2.1.1.3 Certificados Obrigatoriamente Referenciados

O atributo signingCertificate deve conter referência apenas ao certificado do signatário.

## 5.2.1.1.4 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: nenhum certificado.

A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 42 -->
<!-- START OF PAGE 43 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) Até a versão 2.2: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Conjunto de Restrições de Algoritmos

### 5.2.3.1 Restrições de Algoritmos para Signatários

#### 5.2.3.1.1 Restrições de Algoritmos

##### 5.2.3.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0: sha1withRSAEncryption (1 2 840 113549 1 1 5);

b) para a versão 1.1: sha1withRSAEncryption (1 2 840 113549 1 1 5) ou sha256WithRSAEncryption (1.2.840.113549.1.1.11);

c) para as versões 2.0 e 2.1: sha256WithRSAEncryption (1.2.840.113549.1.1.11);

d) para a versão 2.2 e 2.3: sha256WithRSAEncryption (1.2.840.113549.1.1.11) ou sha512WithRSAEncryption (1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

e) para a versão 2.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ou id-Ed448ph (1.3.101.115). (Incluído pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 43 -->
<!-- START OF PAGE 44 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

## 5.2.3.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0: 1024 bits;

b) para a versão 1.1: 1024 bits;

c) para as versões 2.0, 2.1, 2.2 e 2.3: 2048 bits; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

d) para a versão 2.4: (Incluído pela Instrução Normativa ITI n° 33, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

id-Ed25519 e id-Ed25519ph: 256 bits.

id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 44 -->
<!-- START OF PAGE 45 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
44

# 2 POLÍTICA-PADRÃO AD-RT BASEADA EM CADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.1.1.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO CMS, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.4. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 2.0: 26/12/2011;
d) para a versão 2.1: 06/03/2012;
e) para a versão 2.2: 27/04/2016;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 45 -->
<!-- START OF PAGE 46 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

f) para a versão 2.3: 14/05/2018; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)
g) para a versão 2.4: 12/06/2025. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name “C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI”.

## 4 Campo de Aplicação

Este tipo de assinatura deve ser utilizado em aplicações ou processos de negócios nos quais a assinatura digital necessita de segurança em relação à irretratabilidade do momento de sua geração.

Como esse tipo de assinatura não traz, de forma autocontida, referências ou valores dos certificados e das informações de revogação (LCRs ou respostas OCSP) necessários para sua validação posterior, ele deve ser utilizado somente quando esses dados puderem ser obtidos por meios externos, de forma inequívoca. Uma assinatura desse tipo pode ter sua capacidade probante diminuída, no caso de comprometimento da chave da AC que emitiu qualquer um dos certificados da cadeia de certificação.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

## 5 Política de Validação da Assinatura

### 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 06/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.3, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

### 5.2 Regras Comuns

#### 5.2.1 Regras de Signatário e Verificador

##### 5.2.1.1 Regras do Signatário

###### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 46 -->
<!-- START OF PAGE 47 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA devem conter, obrigatoriamente, os seguintes atributos assinados:

a) id-contentType;
b) id-messageDigest;
c.1) Para as versões 1.0, 1.1 e 2.0, id-aa-signingCertificate;
c.2) A partir da versão 2.1, inclusive, id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

# 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA devem conter, obrigatoriamente, o atributo não assinado id-aa-signatureTimeStampToken.

# 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo signingCertificate deve conter referência apenas ao certificado do signatário.

# 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: nenhum certificado

A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

# 5.2.1.2 Regras do Verificador

## 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenha sido incluído pelo signatário, o atributo id-aa-signatureTimeStampToken DEVE ser incluído pelo verificador.

# 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

## 5.2.2.1 Requisitos de Certificados

### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0:

http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 47 -->
<!-- START OF PAGE 48 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.2: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade de Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 48 -->
<!-- START OF PAGE 49 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
www.icpbrasil.gov.br

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.2: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.4 Conjunto de Restrições de Algoritmos

### 5.2.4.1 Restrições de Algoritmos para Signatários

#### 5.2.4.1.1 Restrições de Algoritmos

##### 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo :

a) para a versão 1.0: sha1withRSAEncryption(1 2 840 113549 1 1 5);

b) para a versão 1.1: sha1withRSAEncryption(1 2 840 113549 1 1 5) ou sha256WithRSAEncryption(1.2.840.113549.1.1.11);

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
48

<!-- END OF PAGE 49 -->
<!-- START OF PAGE 50 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

c) para as versões 2.0 e 2.1: sha256WithRSAEncryption(1.2.840.113549.1.1.11);
d) para a versão 2.2 e 2.3: sha256WithRSAEncryption(1.2.840.113549.1.1.11) ou sha512WithRSAEncryption(1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)
e) para a versão 2.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ou id-Ed448ph (1.3.101.115). (Incluído pela Instrução Normativa ITI n° 33, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

## 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de :

a) para a versão 1.0: 1024 bits;
b) para a versão 1.1: 1024 bits;
c) para as versões 2.0, 2.1, 2.2 e 2.3: 2048 bits; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)
d) para a versão 2.4: (Incluído pela Instrução Normativa ITI n° 33, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.
id-Ed25519 e id-Ed25519ph: 256 bits.
id-Ed448 e id-Ed448ph: 456 bits

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 50 -->
<!-- START OF PAGE 51 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
NITR

# 3 POLÍTICA-PADRÃO AD-RV BASEADA EM CADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.1.1.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO CMS, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.4. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 2.0: 26/12/2011;
d) para a versão 2.1: 06/03/2012;
e) para a versão 2.2: 27/04/2016;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 51 -->
<!-- START OF PAGE 52 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

f) para a versão 2.3: 14/05/2018; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)
g) para a versão 2.4: 12/06/2025. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

# 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name “C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI”.

# 4 Campo de Aplicação

Este tipo de assinatura inclui, no seu próprio corpo, referências sobre os certificados que compõem a cadeia de certificação e sobre as informações de revogação do certificado digital do signatário. Um carimbo do tempo provê a ligação entre essas informações e o conteúdo assinado.

Ele deve ser usado em aplicações onde se necessita verificar a assinatura a qualquer momento e onde os dados necessários para isso (que estão referenciados no corpo da assinatura), estejam disponíveis para recuperação.

Além de oferecer segurança quanto à irretratabilidade, ele permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário, desde que o carimbo do tempo sobre as referências tenha sido colocado antes desse comprometimento.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 06/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.3, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 52 -->
<!-- START OF PAGE 53 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.1.1 Regras do Signatário

## 5.2.1.1.1 Dados Externos ou Internos à Assinatura

O conteúdo assinado pode ser tanto interno quanto externo à assinatura.

## 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA devem conter, obrigatoriamente, os seguintes atributos assinados:

a) id-contentType;
b) id-messageDigest;
c.1) Para as versões 1.0, 1.1 e 2.0, id-aa-signingCertificate;
c.2) A partir da versão 2.1, inclusive, id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

## 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA devem conter, obrigatoriamente, os seguintes atributos não assinados:

a) id-aa-signatureTimeStampToken;
b) id-aa-ets-certificateRefs;
c) id-aa-ets-revocationRefs;
d) id-aa-ets-escTimeStamp.

## 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo *signingCertificate* deve conter apenas referência ao certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios da Cadeia de Certificação

Para a versão 1.0: nenhum certificado

A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídos pelo signatário, os seguintes atributos DEVEM ser incluídos pelo verificador:

a) id-aa-signatureTimeStampToken;
b) id-aa-ets-certificateRefs;
c) id-aa-ets-revocationRefs;
d) id-aa-ets-escTimeStamp.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 53 -->
<!-- START OF PAGE 54 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
nha

# 5.2.2.1 Requisitos de Certificados

## 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.2: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

#### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 54 -->
<!-- START OF PAGE 55 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
nha

# 5.2.3 Condições de Confiabilidade de Carimbo do Tempo

## 5.2.3.1 Requisitos de Certificados

### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

### 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.2: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

#### 5.2.3.2.2 Requisitos de Revogação de Certificados de ACs

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 55 -->
<!-- START OF PAGE 56 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.4 Conjunto de Restrições de Algoritmos

## 5.2.4.1 Restrições de Algoritmos para Signatário

### 5.2.4.1.1 Restrições de Algoritmos

#### 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0: sha1withRSAEncryption (1 2 840 113549 1 1 5);
b) para a versão 1.1: sha1withRSAEncryption (1 2 840 113549 1 1 5) ou sha256WithRSAEncryption (1.2.840.113549.1.1.11);
c) para as versões 2.0 e 2.1: sha256WithRSAEncryption (1.2.840.113549.1.1.11);
d) para a versão 2.2 e 2.3: sha256WithRSAEncryption (1.2.840.113549.1.1.11) ou sha512WithRSAEncryption (1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
e) para a versão 2.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ouid-Ed448ph (1.3.101.115). (Incluído pela Instrução Normativa ITI nº 33, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

### 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0: 1024 bits;
b) para a versão 1.1: 1024 bits;
c) para as versões 2.0, 2.1, 2.2 e 2.3: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
d) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.
id-Ed25519 e id-Ed25519ph: 256 bits.
id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 56 -->
<!-- START OF PAGE 57 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
#

# 4 POLÍTICA-PADRÃO AD-RC BASEADA EM CADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.1.1.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO CMS, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.4. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 2.0: 26/12/2011;
d) para a versão 2.1: 06/03/2012;
e) para a versão 2.2: 27/04/2016;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 57 -->
<!-- START OF PAGE 58 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

#

f) para a versão 2.3: 14/05/2018; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)
g) para a versão 2.4: 12/06/2025. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

# 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI".

# 4 Campo de Aplicação

Este tipo de assinatura inclui, no seu próprio corpo, além das referências, os certificados que compõem a cadeia de certificação e as informações de revogação do certificado digital do signatário. Ele demanda uma maior capacidade de armazenamento.

Ele deve ser usado em situações onde é necessária a verificação completa da validade da assinatura digital a qualquer momento, pois os dados necessários estão autocontidos na assinatura.

Além de oferecer segurança quanto à irretratabilidade, ele permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário, desde que o carimbo do tempo sobre as referências/valores dos certificados tenha sido colocado antes desse comprometimento.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 06/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.3, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 58 -->
<!-- START OF PAGE 59 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.1.1 Regras do Signatário

## 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

## 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos assinados:

a) id-contentType;
b) id-messageDigest;
c.1) Para as versões 1.0, 1.1 e 2.0, id-aa-signingCertificate;
c.2) A partir da versão 2.1, inclusive, id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

## 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos não-assinados:

a) id-aa-signatureTimeStampToken;
b) id-aa-ets-certificateRefs;
c) id-aa-ets-revocationRefs;
d) id-aa-ets-escTimeStamp;
e) id-aa-ets-certValues;
f) id-aa-ets-revocationValues.

## 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo *signingCertificate* deve conter referência apenas para o certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios no Caminho de Certificação

Para a versão 1.0: os certificados do caminho de certificação completo do signatário; A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.1.1.6 Regras Adicionais do Signatário

## 5.2.1.2 Regras do Verificador

## 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídos pelo signatário, os seguintes atributos DEVEM ser incluídos pelo verificador:

a) id-aa-signatureTimeStampToken;
b) id-aa-ets-certificateRefs;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 59 -->
<!-- START OF PAGE 60 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

c) id-aa-ets-revocationRefs;
d) id-aa-ets-escTimeStamp;
e) id-aa-ets-certValues;
f) id-aa-ets-revocationValues.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICPBrasil, disponíveis em:

a) para a versão 1.0:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.2: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

### 5.2.2.2 Requisitos de Revogação

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 60 -->
<!-- START OF PAGE 61 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
^{}[]吕

# 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

## 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

## 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0 e 2.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.2 e 2.3:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.4: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.2: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.3: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 61 -->
<!-- START OF PAGE 62 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

5.2.3.2 Requisitos de Revogação
5.2.3.2.1 Requisitos de Revogação para Certificados Finais
5.2.3.2.1.1 Mecanismos de Revogação para Certificados
LCR ou OCSP.

5.2.3.2.2 Requisitos de Revogação para Certificados de ACs
5.2.3.2.2.1 Mecanismos de Revogação para Certificados
LCR ou OCSP.

5.2.4 Conjunto de Restrições de Algoritmos
5.2.4.1 Restrições de Algoritmos para Signatário
5.2.4.1.1 Restrições de Algoritmos
5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0: sha1withRSAEncryption (1 2 840 113549 1 1 5);
b) para a versão 1.1: sha1withRSAEncryption (1 2 840 113549 1 1 5) ou sha256WithRSAEncryption (1.2.840.113549.1.1.11);
c) para as versões 2.0 e 2.1: sha256WithRSAEncryption (1.2.840.113549.1.1.11);
d) para a versão 2.2 e 2.3: sha256WithRSAEncryption (1.2.840.113549.1.1.11) ou sha512WithRSAEncryption (1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
e) para a versão 2.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113) id-Ed448ph (1.3.101.115). (Incluído pela Instrução Normativa ITI nº 33, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de :

a) para a versão 1.0: 1024 bits;
b) para a versão 1.1: 1024 bits;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 62 -->
<!-- START OF PAGE 63 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

c) para as versões 2.0, 2.1, 2.2 e 2.3: 2048 bits; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

d) para a versão 2.4: (Incluído pela Instrução Normativa ITI n° 33, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.
id-Ed25519 e id-Ed25519ph: 256 bits.
id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
62

<!-- END OF PAGE 63 -->
<!-- START OF PAGE 64 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 5 POLÍTICA-PADRÃO AD-RA BASEADA EM CADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.1.2.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.2.4.

O nome desta Política de Assinatura para a versão 2.5 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO CMS, versão 2.5 e o seu Object Identifier (OID) é 2.16.76.1.7.1.5.2.5. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 64 -->
<!-- START OF PAGE 65 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 1.2: 21/09/2012;
d) para a versão 2.0: 26/12/2011;
e) para a versão 2.1: 06/03/2012;
f) para a versão 2.2: 21/09/2012;
g) para a versão 2.3: 27/04/2016;
h) para a versão 2.4: 14/05/2018; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
i) para a versão 2.5: 12/06/2025. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 3 Nome da Entidade emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI".

## 4 Campo de Aplicação

Este tipo de assinatura é adequado para aplicações que necessitam realizar o arquivamento do conteúdo digital assinado por longos períodos, sabendo-se que podem surgir fraquezas, vulnerabilidades ou exposição a fragilidades dos algoritmos, funções e chaves criptográficas utilizadas no processo de geração de assinatura digital.

Ele provê proteção contra fraqueza dos algoritmos, funções e tamanho de chaves criptográficas, desde que o carimbo do tempo de arquivamento seja realizado tempestivamente e utilize algoritmos, funções e tamanhos de chave considerados seguros no momento de sua geração.

Além disso, oferece segurança quanto à irretratabilidade, e permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário (desde que o carimbo do tempo sobre as referências/valores dos certificados tenha sido colocado antes desse comprometimento).

## 5 Política de Validação da Assinatura

### 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 1.2, o período para assinatura desta PA é de 21/09/2011 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 65 -->
<!-- START OF PAGE 66 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Para a versão 2.1, o período para assinatura desta PA é de 06/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 21/09/2012 a 21/06/2023.
Para a versão 2.3, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.5, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos assinados:

a) id-contentType;
b) id-messageDigest;
c.1) Para as versões 1.0, 1.1 e 2.0, id-aa-signingCertificate;
c.2) Para as versões 1.2, 2.1, 2.2, 2.3, 2.4 e 2.5, id-aa-signingCertificateV2; (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
d) id-aa-ets-sigPolicyId.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos não-assinados:

Para as versões 1.0, 1.1, 2.0 e 2.1:

a) id-aa-signatureTimeStampToken;
b) id-aa-ets-certificateRefs;
c) id-aa-ets-revocationRefs;
d) id-aa-ets-certValues;
e) id-aa-ets-revocationValues;
f) id-aa-ets-archiveTimestampV2.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

a) id-aa-ets-certificateRefs;
b) id-aa-ets-revocationRefs;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 66 -->
<!-- START OF PAGE 67 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
e)
iCP

c) id-aa-ets-certValues;
d) id-aa-ets-revocationValues;
e) id-aa-ets-archiveTimestampV2.

## 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo *signingCertificate* deve conter referência apenas para o certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: os certificados do caminho de certificação completo do signatário;
A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídos pelo signatário, os seguintes atributos DEVEM ser incluídos pelo verificador:

Para as versões 1.0, 1.1, 2.0 e 2.1:

a) id-aa-signatureTimeStampToken;
b) id-aa-ets-certificateRefs;
c) id-aa-ets-revocationRefs;
d) id-aa-ets-certValues;
e) id-aa-ets-revocationValues;
f) id-aa-ets-archiveTimestampV2.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

a) id-aa-ets-certificateRefs;
b) id-aa-ets-revocationRefs;
c) id-aa-ets-certValues;
d) id-aa-ets-revocationValues;
e) id-aa-ets-archiveTimestampV2.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 67 -->
<!-- START OF PAGE 68 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0, 2.1 e 2.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 68 -->
<!-- START OF PAGE 69 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
nha

# 5.2.3.1 Requisitos de Certificados

## 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para as versões 2.0, 2.1 e 2.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

### 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 69 -->
<!-- START OF PAGE 70 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
LCR ou OCSP.

# 5.2.4 Conjunto de Restrições de Algoritmos

## 5.2.4.1 Restrições de Algoritmos para Signatário

### 5.2.4.1.1 Restrições de Algoritmos

#### 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo :

a) para a versão 1.0: sha1withRSAEncryption (1 2 840 113549 1 1 5);
b) para a versão 1.1 e 1.2: sha1withRSAEncryption (1 2 840 113549 1 1 5) ou sha256WithRSAEncryption (1.2.840.113549.1.1.11);
c) para as versões 2.0, 2.1 e 2.2: sha256WithRSAEncryption (1.2.840.113549.1.1.11);
d) para a versão 2.3 e 2.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11) ou sha512WithRSAEncryption (1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
e) para a versão 2.5: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ou id-Ed448ph (1.3.101.115). (Incluído pela Instrução Normativa ITI nº 33, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

#### 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0: 1024 bits;
b) para a versão 1.1 e 1.2: 1024 bits;
c) para as versões 2.0, 2.1, 2.2, 2.3 e 2.4: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
d) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.
id-Ed25519 e id-Ed25519ph: 256 bits.
id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 70 -->
<!-- START OF PAGE 71 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
#

# 6 POLÍTICA-PADRÃO AD-RB BASEADA EM XADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.1.2.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.4.

O nome desta Política de Assinatura para a versão 2.5 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO XML-DSig, versão 2.5 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.5. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
70

<!-- END OF PAGE 71 -->
<!-- START OF PAGE 72 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 1.2: 21/09/2012;
d) para a versão 2.0: 26/12/2011;
e) para a versão 2.1: 22/03/2012;
f) para a versão 2.2: 21/09/2012;
g) para a versão 2.3: 27/04/2016;
h) para a versão 2.4: 14/05/2018; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
i) para a versão 2.5: 12/06/2025. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI".

## 4 Campo de Aplicação

Este tipo de assinatura deve ser utilizado em aplicações ou processos de negócio nos quais a assinatura digital agrega segurança à autenticação de entidades e verificação de integridade, permitindo sua validação durante o prazo de validade dos certificados dos signatários.

Uma vez que não são usados carimbos do tempo, a validação posterior só será possível se existirem referências temporais que identifiquem o momento em que ocorreu a assinatura digital. Nessas situações, deve existir legislação específica ou um acordo prévio entre as partes definindo as referências a serem utilizadas.

## 5 Política de Validação da Assinatura

### 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 1.2, o período para assinatura desta PA é de 21/09/2012 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 22/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 21/09/2012 a 21/06/2023.
Para a versão 2.3, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.5, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 72 -->
<!-- START OF PAGE 73 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2 Regras Comuns

## 5.2.1 Regras de Signatário e Verificador

### 5.2.1.1 Regras do Signatário

#### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

#### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades assinadas:

Para as versões 1.0, 1.1, 2.0 e 2.1:

- a) DataObjectFormat (em assinaturas do tipo detached);
- b) SigningCertificate;
- c) SignaturePolicyIdentifier.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

- a) SigningCertificate;
- b) SignaturePolicyIdentifier.

#### 5.2.1.1.3 Certificados Obrigatoriamente Referenciados

A propriedade SigningCertificate deve conter apenas referência ao certificado do signatário.

#### 5.2.1.1.4 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: nenhum certificado;

A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICPBrasil, disponíveis em:

- a) para a versão 1.0 e 1.2:
- http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt
- http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;
- b) para a versão 1.1:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 73 -->
<!-- START OF PAGE 74 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Conjunto de Restrições de Algoritmos

### 5.2.3.1 Restrições de Algoritmos para Signatário

#### 5.2.3.1.1 Restrições de Algoritmos

##### 5.2.3.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.2: http://www.w3.org/2000/09/xmldsig#rsa-sha1;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 74 -->
<!-- START OF PAGE 75 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

b) para a versão 1.1: http://www.w3.org/2000/09/xmldsig#rsa-sha1 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;
c) para a versão 2.0, 2.1 e 2.2: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;
d) para a versão 2.3 e 2.4: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
e) para a versão 2.5: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256; http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256; ou http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 1024 bits;
b) para a versão 2.0, 2.1, 2.2, 2.3 e 2.4: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
c) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 75 -->
<!-- START OF PAGE 76 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 7 POLÍTICA-PADRÃO AD-RT BASEADA EM XADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.1.2.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.4.

O nome desta Política de Assinatura para a versão 2.5 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO XML-DSig, versão 2.5 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.5. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 76 -->
<!-- START OF PAGE 77 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 1.2: 21/09/2012;
d) para a versão 2.0: 26/12/2011;
e) para a versão 2.1: 22/03/2012;
f) para a versão 2.2: 21/09/2012;
g) para a versão 2.3: 27/04/2016;
h) para a versão 2.4: 14/05/2018; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)
i) para a versão 2.5: 12/06/2025. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI".

## 4 Campo de Aplicação

Este tipo de assinatura deve ser utilizado em aplicações ou processos de negócios nos quais a assinatura digital necessita de segurança em relação à irretratabilidade do momento de sua geração.

Como esse tipo de assinatura não traz, de forma autocontida, referências ou valores dos certificados e das informações de revogação (LCRs ou respostas OCSP) necessários para sua validação posterior, ele deve ser utilizado somente quando esses dados puderem ser obtidos por meios externos, de forma inequívoca. Uma assinatura desse tipo pode ter sua capacidade probante diminuída, no caso de comprometimento da chave da AC que emitiu qualquer um dos certificados da cadeia de certificação.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

## 5 Política de Validação da Assinatura

Os campos a seguir definem os processos para geração e verificação de assinaturas realizadas segundo esta PA.

### 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 1.2, o período para assinatura desta PA é de 21/09/2012 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 22/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 21/09/2012 a 21/06/2023.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 77 -->
<!-- START OF PAGE 78 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Para a versão 2.3, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.5, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades assinadas:

Para as versões 1.0, 1.1, 2.0 e 2.1:

- a) DataObjectFormat (em assinaturas do tipo detached);
- b) SigningCertificate;
- c) SignaturePolicyIdentifier.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

- a) SigningCertificate;
- b) SignaturePolicyIdentifier.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades não assinadas:

- a) SignatureTimeStamp.

##### 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

A propriedade SigningCertificate deve conter apenas referência ao certificado do signatário.

##### 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: nenhum certificado;

A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

#### 5.2.1.2 Regras do Verificador

##### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 78 -->
<!-- START OF PAGE 79 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Caso não tenha sido incluída pelo signatário, a seguinte propriedade DEVE ser incluída pelo verificador:

a) SignatureTimeStamp.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICPBrasil, disponíveis em :

a) para a versão 1.0 e 1.2:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt

d) para a versão 2.3 e 2.4:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

### 5.2.2.2 Requisitos de Revogação

#### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 79 -->
<!-- START OF PAGE 80 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

LCR ou OCSP.

## 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:

http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt.

e) para a versão 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até versão 2.3: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

### 5.2.3.2 Requisitos de Revogação

#### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 80 -->
<!-- START OF PAGE 81 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

# 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.4 Conjunto de Restrições de Algoritmos

# 5.2.4.1 Restrições de Algoritmos para Signatário

# 5.2.4.1.1 Restrições de Algoritmos

# 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.2: http://www.w3.org/2000/09/xmldsig#rsa-sha1;

b) para a versão 1.1: http://www.w3.org/2000/09/xmldsig#rsa-sha1 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;

c) para a versão 2.0, 2.1 e 2.2: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;

d) para a versão 2.3 e 2.4: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

e) para a versão 2.5: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256; http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256; ou http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

# 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 1024 bits;

b) para a versão 2.0, 2.1, 2.2, 2.3 e 2.4: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

c) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 81 -->
<!-- START OF PAGE 82 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
8 POLÍTICA-PADRÃO AD-RV BASEADA EM XADES

# 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.1.2.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.4.

O nome desta Política de Assinatura para a versão 2.5 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA VALIDAÇÃO NO FORMATO XML-DSig, versão 2.5 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.5. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

# 2 Data de Emissão

A data de emissão de cada PA é:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
81

<!-- END OF PAGE 82 -->
<!-- START OF PAGE 83 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 1.2: 21/09/2012;
d) para a versão 2.0: 26/12/2011;
e) para a versão 2.1: 22/03/2012;
f) para a versão 2.2: 21/09/2012;
g) para a versão 2.3: 27/04/2016;
h) para a versão 2.4: 14/05/2018; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
i) para a versão 2.5: 12/06/2025. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI".

## 4 Campo de Aplicação

Este tipo de assinatura inclui, no seu próprio corpo, referências sobre os certificados que compõem a cadeia de certificação e sobre as informações de revogação do certificado digital do signatário. Um carimbo do tempo provê a ligação entre essas informações e o conteúdo assinado.

Ele deve ser usado em aplicações onde se necessita verificar a assinatura a qualquer momento e onde os dados necessários para isso (que estão referenciados no corpo da assinatura), estejam disponíveis para recuperação.

Além de oferecer segurança quanto à irretratabilidade, ele permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário, desde que o carimbo do tempo sobre as referências tenha sido colocado antes desse comprometimento.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

## 5 Política de Validação da Assinatura

### 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 1.2, o período para assinatura desta PA é de 21/09/2012 a 31/12/2014.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 83 -->
<!-- START OF PAGE 84 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 22/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 21/09/2012 a 21/06/2023.
Para a versão 2.3, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.5, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades assinadas:

Para as versões 1.0, 1.1, 2.0 e 2.1:

- a) DataObjectFormat (em assinaturas do tipo detached);
- b) SigningCertificate;
- c) SignaturePolicyIdentifier.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

- a) SigningCertificate;
- b) SignaturePolicyIdentifier.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades não assinadas:

- a) SignatureTimeStamp;
- b) CompleteCertificateRefs;
- c) CompleteRevocationRefs;
- d) SigAndRefsTimeStamp.

##### 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

A propriedade SigningCertificate deve conter apenas referência ao certificado do signatário.

##### 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 84 -->
<!-- START OF PAGE 85 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Para a versão 1.0: nenhum certificado;
A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídas pelo signatário, as seguintes propriedades DEVEM ser incluídas pelo verificador:

- a) SignatureTimeStamp;
- b) CompleteCertificateRefs;
- c) CompleteRevocationRefs;
- d) SigAndRefsTimeStamp.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICPBrasil, disponíveis em:

- a) para a versão 1.0 e 1.2:
- http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;
- b) para a versão 1.1:
- http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;
- c) para a versão 2.0, 2.1 e 2.2:
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;
- d) para a versão 2.3 e 2.4:
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;
- e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 85 -->
<!-- START OF PAGE 86 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) Até a versão 2.3: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

#### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:

http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 86 -->
<!-- START OF PAGE 87 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

#### 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.4 Conjunto de Restrições de Algoritmos

### 5.2.4.1 Restrições de Algoritmos para Signatário

#### 5.2.4.1.1 Restrições de Algoritmos

##### 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.2: http://www.w3.org/2000/09/xmldsig#rsa-sha1;

b) para a versão 1.1: http://www.w3.org/2000/09/xmldsig#rsa-sha1 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;

c) para a versão 2.0, 2.1 e 2.2: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;

d) para a versão 2.3 e 2.4: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 87 -->
<!-- START OF PAGE 88 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

e) para a versão 2.5: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256; http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256; ou http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 1024 bits;

b) para a versão 2.0, 2.1, 2.2, 2.3 e 2.4: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

c) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 88 -->
<!-- START OF PAGE 89 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
#

# 9 POLÍTICA-PADRÃO AD-RC BASEADA EM XADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.1.2.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.4.

O nome desta Política de Assinatura para a versão 2.5 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO XML-DSig, versão 2.5 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.5. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
88

<!-- END OF PAGE 89 -->
<!-- START OF PAGE 90 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
^{}[]℠

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 1.2: 21/09/2012;
d) para a versão 2.0: 26/12/2011;
e) para a versão 2.1: 22/03/2012;
f) para a versão 2.2: 21/09/2012;
g) para a versão 2.3: 27/04/2016;
h) para a versão 2.4: 14/05/2018; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
i) para a versão 2.5: 12/06/2025. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

# 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI".

# 4 Campo de Aplicação

Este tipo de assinatura inclui, no seu próprio corpo, além das referências, os certificados que compõem a cadeia de certificação e as informações de revogação do certificado digital do signatário. Ele demanda uma maior capacidade de armazenamento.

Ele deve ser usado em situações onde é necessária a verificação completa da validade da assinatura digital a qualquer momento, pois os dados necessários estão autocontidos na assinatura.

Além de oferecer segurança quanto à irretratabilidade, ele permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário, desde que o carimbo do tempo sobre as referências/valores dos certificados tenha sido colocado antes desse comprometimento.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 1.2, o período para assinatura desta PA é de 21/09/2012 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 90 -->
<!-- START OF PAGE 91 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Para a versão 2.1, o período para assinatura desta PA é de 22/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 21/09/2012 a 21/06/2023.
Para a versão 2.3, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.5, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades assinadas:

Para as versões 1.0, 1.1, 2.0 e 2.1:

- a) DataObjectFormat (em assinaturas do tipo detached);
- b) SigningCertificate;
- c) SignaturePolicyIdentifier.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

- a) SigningCertificate;
- b) SignaturePolicyIdentifier.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades não assinadas:

- a) SignatureTimeStamp;
- b) CompleteCertificateRefs;
- c) CompleteRevocationRefs;
- d) SigAndRefsTimeStamp;
- e) CertificateValues;
- f) RevocationValues.

##### 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 91 -->
<!-- START OF PAGE 92 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

A propriedade SigningCertificate deve conter apenas referência ao certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: os certificados do caminho de certificação completo do signatário;
A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídas pelo signatário, as seguintes propriedades DEVEM ser incluídas pelo verificador:

- a) SignatureTimeStamp;
- b) CompleteCertificateRefs;
- c) CompleteRevocationRefs;
- d) SigAndRefsTimeStamp;
- e) CertificateValues;
- f) RevocationValues.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

- a) para a versão 1.0 e 1.2:
- http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;
- b) para a versão 1.1:
- http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;
- c) para a versão 2.0, 2.1 e 2.2:
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;
- d) para a versão 2.3 e 2.4:
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;
- e) para a versão 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 92 -->
<!-- START OF PAGE 93 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 93 -->
<!-- START OF PAGE 94 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].
b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.4 Conjunto de Restrições de Algoritmos

### 5.2.4.1 Restrições de Algoritmos para Signatário

#### 5.2.4.1.1 Restrições de Algoritmos

##### 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.2: http://www.w3.org/2000/09/xmldsig#rsa-sha1;
b) para a versão 1.1: http://www.w3.org/2000/09/xmldsig#rsa-sha1 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;
c) para a versão 2.0, 2.1, 2.2: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;
d) para a versão 2.3 e 2.4: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 94 -->
<!-- START OF PAGE 95 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

e) para a versão 2.5: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256; http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256; ou http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 1024 bits;

b) para a versão 2.0, 2.1, 2.2, 2.3 e 2.4: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

c) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 95 -->
<!-- START OF PAGE 96 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
10 POLÍTICA-PADRÃO AD-RA BASEADA EM XADES

# 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.1.2.

O nome desta Política de Assinatura para a versão 2.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.2.

O nome desta Política de Assinatura para a versão 2.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.2.1.

O nome desta Política de Assinatura para a versão 2.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 2.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.2.2.

O nome desta Política de Assinatura para a versão 2.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 2.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.2.3.

O nome desta Política de Assinatura para a versão 2.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 2.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.2.4.

O nome desta Política de Assinatura para a versão 2.5 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO XML-DSig, versão 2.5 e o seu Object Identifier (OID) é 2.16.76.1.7.1.10.2.5. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

# 2 Data de Emissão

A data de emissão de cada PA é:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
95

<!-- END OF PAGE 96 -->
<!-- START OF PAGE 97 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) para a versão 1.0: 31/10/2008;
b) para a versão 1.1: 26/12/2011;
c) para a versão 1.2: 21/09/2012;
d) para a versão 2.0: 26/12/2011;
e) para a versão 2.1: 22/03/2012;
f) para a versão 2.2: 21/09/2012;
g) para a versão 2.3: 27/04/2016;
h) para a versão 2.4: 14/05/2018; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
i) para a versão 2.5: 12/06/2025; (Incluído pela Instrução Normativa ITI nº 33, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name “C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI”.

## 4 Campo de Aplicação

Este tipo de assinatura é adequado para aplicações que necessitam realizar o arquivamento do conteúdo digital assinado por longos períodos, sabendo-se que podem surgir fraquezas, vulnerabilidades ou exposição a fragilidades dos algoritmos, funções e chaves criptográficas utilizadas no processo de geração de assinatura digital.

Ele provê proteção contra fraqueza dos algoritmos, funções e tamanho de chaves criptográficas, desde que o carimbo do tempo de arquivamento seja realizado tempestivamente e utilize algoritmos, funções e tamanhos de chave considerados seguros no momento de sua geração.

Além disso, oferece segurança quanto à irretratabilidade, e permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário (desde que o carimbo do tempo sobre as referências/valores dos certificados tenha sido colocado antes desse comprometimento).

## 5 Política de Validação da Assinatura

Os campos a seguir definem os processos para geração e verificação de assinaturas realizadas segundo esta PA.

### 5.1 Período para Assinatura

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 97 -->
<!-- START OF PAGE 98 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
Para a versão 1.1, o período para assinatura desta PA é de 26/12/2011 a 31/12/2014.
Para a versão 1.2, o período para assinatura desta PA é de 21/09/2012 a 31/12/2014.
Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
Para a versão 2.1, o período para assinatura desta PA é de 22/03/2012 a 21/06/2023.
Para a versão 2.2, o período para assinatura desta PA é de 21/09/2012 a 21/06/2023.
Para a versão 2.3, o período para assinatura desta PA é de 27/04/2016 a 02/03/2029.
Para a versão 2.4, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 2.5, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado pode ser tanto externo quanto interno à assinatura

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades assinadas:

Para as versões 1.0, 1.1, 2.0 e 2.1:

a) DataObjectFormat (em assinaturas do tipo detached);
b) SigningCertificate;
c) SignaturePolicyIdentifier.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

a) SigningCertificate;
b) SignaturePolicyIdentifier.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórias as seguintes propriedades não assinadas:

Para as versões 1.0, 1.1, 2.0 e 2.1:

a) SignatureTimeStamp;
b) CompleteCertificateRefs;
c) CompleteRevocationRefs;
d) CertificateValues;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 98 -->
<!-- START OF PAGE 99 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
e) RevocationValues;
f) ArchiveTimeStamp.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

a) CompleteCertificateRefs;
b) CompleteRevocationRefs;
c) CertificateValues;
d) RevocationValues;
e) ArchiveTimeStamp.

## 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

A propriedade SigningCertificate deve conter apenas referência ao certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0: os certificados do caminho de certificação completo do signatário;
A partir da versão 1.1: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídas pelo signatário, as seguintes propriedades DEVEM ser incluídas pelo verificador:

Para as versões 1.0, 1.1, 2.0 e 2.1:

a) SignatureTimeStamp;
b) CompleteCertificateRefs;
c) CompleteRevocationRefs;
d) CertificateValues;
e) RevocationValues;
f) ArchiveTimeStamp.

Para as versões 1.2, 2.2, 2.3, 2.4 e 2.5: (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

a) CompleteCertificateRefs;
b) CompleteRevocationRefs;
c) CertificateValues;
d) RevocationValues;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
98

<!-- END OF PAGE 99 -->
<!-- START OF PAGE 100 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
e) ArchiveTimeStamp.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:
http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:
http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

### 5.2.2.2 Requisitos de Revogação

#### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
99

<!-- END OF PAGE 100 -->
<!-- START OF PAGE 101 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

# 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

# 5.2.3.1 Requisitos de Certificados

# 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.2:

http://acraiz.icpbrasil.gov.br/Certificado_AC_Raiz.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt;

b) para a versão 1.1:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

c) para a versão 2.0, 2.1 e 2.2:

http://acraiz.icpbrasil.gov.br/ICP-Brasil.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt;

d) para a versão 2.3 e 2.4:

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

e) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

# 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Até a versão 2.3: Os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 2.4: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

# 5.2.3.2 Requisitos de Revogação

# 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 101 -->
<!-- START OF PAGE 102 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

# 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.4 Conjunto de Restrições de Algoritmos

# 5.2.4.1 Restrições de Algoritmos para Signatário

# 5.2.4.1.1 Restrições de Algoritmos

# 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.2: http://www.w3.org/2000/09/xmldsig#rsa-sha1;

b) para a versão 1.1: http://www.w3.org/2000/09/xmldsig#rsa-sha1 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;

c) para a versão 2.0, 2.1 e 2.2: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256;

d) para a versão 2.3 e 2.4: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ou http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

e) para a versão 2.5: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256; http://www.w3.org/2001/04/xmldsig-more#rsa-sha512; http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256; ou http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

# 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 1024 bits;

b) para a versão 2.0, 2.1, 2.2, 2.3 e 2.4: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

c) para a versão 2.5: (Incluído pela Instrução Normativa ITI nº 33, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 102 -->
<!-- START OF PAGE 103 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 11 POLÍTICA-PADRÃO AD-RB BASEADA EM PADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO PDF, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.11.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO PDF, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.11.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO PDF, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.11.1.2. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

O nome desta Política de Assinatura para a versão 1.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO PDF, versão 1.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.11.1.3. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 25/08/2015;
b) para a versão 1.1: 14/05/2018; (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
c) para a versão 1.2: 12/06/2025; e (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
d) para a versão 1.3: 23/07/2025. (Incluído pela Instrução Normativa ITI nº 34, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informação – ITI".

## 4 Campo de Aplicação

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 103 -->
<!-- START OF PAGE 104 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Este tipo de assinatura deve ser utilizado em aplicações ou processos de negócio nos quais a assinatura digital agrega segurança à autenticação de entidades e verificação de integridade, permitindo sua validação durante o prazo de validade dos certificados dos signatários.

Uma vez que não são usados carimbos do tempo, a validação posterior só será possível se existirem referências temporais que identifiquem o momento em que ocorreu a assinatura digital. Nessas situações, deve existir legislação específica ou um acordo prévio entre as partes definindo as referências a serem utilizadas.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

Esse tipo de PA é aplicável apenas em arquivos do tipo PDF.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 25/08/2015 a 02/03/2029.

Para a versão 1.1, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.

Para a versão 1.2, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Para a versão 1.3, o período para assinatura desta PA é de 23/07/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado deve ser externo à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos assinados:

a) id-contentType;
b) id-messageDigest;
c) id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

Não possui atributos não-assinados obrigatórios.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 104 -->
<!-- START OF PAGE 105 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo *id-aa-signingCertificateV2* deve conter referência apenas ao certificado do signatário.

# 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0, 1.1, 1.2 e 1.3: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

# 5.2.1.1.6 Regras Adicionais do Signatário

## 5.2.1.1.6.1 Extensão br_ext_mandatedPdfSigDicEntries.

### 5.2.1.1.6.1.1 Entradas obrigatórias do Dicionário de Assinaturas:

- a) Type;
- b) Filter;
- c) SubFilter;
- d) Contents;
- e) ByteRange.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

- a) para a versão 1.0 e 1.1:
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt.
- b) para a versão 1.2 e 1.3: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

- a) Para a versão 1.0: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 105 -->
<!-- START OF PAGE 106 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

b) A partir da versão 1.1: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Conjunto de Restrições de Algoritmos

### 5.2.3.1 Restrições de Algoritmos para Signatários

#### 5.2.3.1.1 Restrições de Algoritmos

##### 5.2.3.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.1: sha256WithRSAEncryption(1.2.840.113549.1.1.11) ou sha512WithRSAEncryption(1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

b) para a versão 1.2 e 1.3: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ou id-Ed448ph (1.3.101.115). (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI nº 33, de 2025)

### 5.2.3.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0 e 1.1: 2048 bits; e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

b) para a versão 1.2 e 1.3: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 106 -->
<!-- START OF PAGE 107 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
id-Ed25519 e id-Ed25519ph: 256 bits.
id-Ed448 e id-Ed448ph: 456 bits.
Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
106

<!-- END OF PAGE 107 -->
<!-- START OF PAGE 108 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 12 POLÍTICA-PADRÃO AD-RT BASEADA EM PADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO PDF, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.12.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO PDF, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.12.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO PDF, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.12.1.2. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

O nome desta Política de Assinatura para a versão 1.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA DO TEMPO NO FORMATO PDF, versão 1.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.12.1.3. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 25/08/2015;
b) para a versão 1.1: 14/05/2018; (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
c) para a versão 1.2: 12/06/2025; e (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
d) para a versão 1.3: 23/07/2025. (Incluído pela Instrução Normativa ITI nº 34, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

A entidade emissora desta PA é identificada pelo Distinguished Name "C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informação – ITI".

## 4 Campo de Aplicação

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 108 -->
<!-- START OF PAGE 109 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Este tipo de assinatura deve ser utilizado em aplicações ou processos de negócios nos quais a assinatura digital necessita de segurança em relação à irretratabilidade do momento de sua geração.

Como esse tipo de assinatura não traz, de forma autocontida, referências ou valores dos certificados e das informações de revogação (LCRs ou respostas OCSP) necessários para sua validação posterior, ele deve ser utilizado somente quando esses dados puderem ser obtidos por meios externos, de forma inequívoca. Uma assinatura desse tipo pode ter sua capacidade probante diminuída, no caso de comprometimento da chave da AC que emitiu qualquer um dos certificados da cadeia de certificação.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

Esse tipo de PA é aplicável apenas em arquivos do tipo PDF.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 25/08/2015 a 02/03/2029.

Para a versão 1.1, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.

Para a versão 1.2, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Para a versão 1.3, o período para assinatura desta PA é de 23/07/2025 a 22/10/2037. (Incluído pela Instrução Normativa ITI nº 34, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado deve ser externo à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA devem conter, obrigatoriamente, os seguintes atributos assinados:

- a) id-contentType;
- b) id-messageDigest;
- c) id-aa-signingCertificateV2;
- d) id-aa-ets-sigPolicyId.

##### 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 109 -->
<!-- START OF PAGE 110 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

As assinaturas feitas segundo esta PA devem conter, obrigatoriamente, o atributo não assinado id-aa-signatureTimeStampToken.

## 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo id-aa-signingCertificateV2 deve conter referência apenas ao certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0, 1.1, 1.2 e 1.3: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 5.2.1.1.6 Regras Adicionais do Signatário

### 5.2.1.1.6.1 Extensão br_ext_mandatedPdfSigDicEntries.

### 5.2.1.1.6.1.1 Entradas obrigatórias do Dicionário de Assinaturas:

- a) Type;
- b) Filter;
- c) SubFilter;
- d) Contents;
- e) ByteRange.

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídos pelo signatário, os seguintes atributos DEVEM ser incluídos pelo verificador:

- a) id-aa-signatureTimeStampToken.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICPBrasil, disponíveis em:

- a) para a versão 1.0 e 1.1:
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;
- b) para a versão 1.2 e 1.3: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
- http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 110 -->
<!-- START OF PAGE 111 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt

## 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Para a versão 1.0: assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 1.1: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade de Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0 e 1.1:

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt;

b) para a versão 1.2 e 1.3: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt

#### 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Para a versão 1.0: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 111 -->
<!-- START OF PAGE 112 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

www.icp-brasil.com

b) a partir da versão 1.1: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.4 Conjunto de Restrições de Algoritmos

### 5.2.4.1 Restrições de Algoritmos para Signatários

#### 5.2.4.1.1 Restrições de Algoritmos

##### 5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0 e 1.1: sha256WithRSAEncryption (1.2.840.113549.1.1.11) ou sha512WithRSAEncryption (1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

b) para a versão 1.2 e 1.3: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ou id-Ed448ph (1.3.101.115). (Redação dada pela Instrução Normativa ITI n° 34, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

### 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0 e 1.1: 2048 bits; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

b) para a versão 1.2 e 1.3: (Redação dada pela Instrução Normativa ITI n° 34, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

id-Ed25519 e id-Ed25519ph: 256 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 112 -->
<!-- START OF PAGE 113 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
112

<!-- END OF PAGE 113 -->
<!-- START OF PAGE 114 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 13 POLÍTICA-PADRÃO AD-RC BASEADA EM PADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO PDF, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.13.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO PDF, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.13.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO PDF, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.13.1.2.

O nome desta Política de Assinatura para a versão 1.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO PDF, versão 1.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.13.1.3. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

O nome desta Política de Assinatura para a versão 1.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS COMPLETAS NO FORMATO PDF, versão 1.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.13.1.4. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 25/08/2015;
b) para a versão 1.1: 15/07/2016;
c) para a versão 1.2: 14/05/2018; (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
d) para a versão 1.3: 12/06/2025; e (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
e) para a versão 1.4: 23/07/2025. (Incluído pela Instrução Normativa ITI nº 34, de 2025)

## 3 Nome da Entidade Emissora da Política de Assinatura

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 114 -->
<!-- START OF PAGE 115 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

A entidade emissora desta PA é identificada pelo Distinguished Name “C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI”.

# 4 Campo de Aplicação

Este tipo de assinatura inclui, no seu próprio corpo, uma referência do tempo da assinatura, os certificados que compõem a cadeia de certificação e as informações de revogação do certificado digital do signatário. Além disso, será acrescentado ou logicamente conectado, sobre todo o conjunto de dados, um carimbo do tempo.

Deve ser usado em situações onde é necessária a verificação completa da validade da assinatura digital a qualquer momento, pois os dados necessários estão auto contidos na assinatura. Este tipo de assinatura demanda uma maior capacidade de armazenamento.

Além de oferecer segurança quanto à irretratabilidade, ele permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário, desde que o carimbo do tempo que foi aplicado sobre todo o conjunto de dados tenha sido colocado antes desse comprometimento.

Segundo esta PA, é permitido o emprego de múltiplas assinaturas.

Este tipo de PA é aplicável apenas em arquivos do tipo PDF.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 25/08/2015 a 02/03/2029.

Para a versão 1.1, o período para assinatura desta PA é de 15/07/2016 a 02/03/2029.

Para a versão 1.2, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.

Para a versão 1.3, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Para a versão 1.4, o período para assinatura desta PA é de 23/07/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado deve ser externo à assinatura.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 115 -->
<!-- START OF PAGE 116 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos assinados:

a) id-contentType;
b) id-messageDigest;
c) id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

# 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos não-assinados:

a) id-aa-signatureTimeStampToken.

# 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo id-aa-signingCertificateV2 deve conter referência apenas para o certificado do signatário.

# 5.2.1.1.5 Certificados Obrigatórios no Caminho de Certificação

Para a versão 1.0, 1.1, 1.2, 1.3 e 1.4: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

# 5.2.1.1.6 Regras Adicionais do Signatário

## 5.2.1.1.6.1 Extensão br_ext_mandatedPdfSigDicEntries.

### 5.2.1.1.6.1.1 Entradas obrigatórias do Dicionário de Assinaturas:

a) Type;
b) Filter;
c) SubFilter;
d) Contents;
e) ByteRange.

### 5.2.1.1.6.2 Extensão br_ext_dss

### 5.2.1.1.6.2.1 Entradas obrigatórias do campo dssDictionary

a) Type;
b) VRI;
c) Certs;

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 116 -->
<!-- START OF PAGE 117 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
#

d) OCSPs ou CRLs (ValidationValues, anexo4).

## 5.2.1.1.6.2.2 Entradas obrigatórias do campo vriDictionary

a) Type;
b) Cert;
c) OCSP ou CRL (ValidationValues, anexo4).

## 5.2.1.1.6.3 Extensão br_ext_mandatedDocTSEntries

Entradas obrigatórias do DocumentTimestamp:

a) Type;
b) SubFilter;
c) Contents.

## 5.2.1.2 Regras do Verificador

### 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídos pelo signatário, os seguintes atributos DEVEM ser incluídos pelo verificador:

a) id-aa-signatureTimeStampToken.

### 5.2.1.2.2 Regras Adicionais do Verificador

5.2.1.2.2.1 Extensão br_ext_dss

5.2.1.2.2.1.1 Entradas obrigatórias do campo dssDictionary

a) Type;
b) VRI;
c) Certs;
d) OCSPs ou CRLs (ValidationValues, anexo4).

5.2.1.2.2.1.2 Entradas obrigatórias do campo vriDictionary

a) Type;
b) Cert;
c) OCSP ou CRL (ValidationValues, anexo4).

5.2.1.2.2.2 Extensão br_ext_mandatedDocTSEntries

Entradas obrigatórias do DocumentTimestamp:

a) Type;
b) SubFilter;
c) Contents.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
116

<!-- END OF PAGE 117 -->
<!-- START OF PAGE 118 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

## 5.2.2.1 Requisitos de Certificados

### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0, 1.1 e 1.2:

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt.

b) para a versão 1.3 e 1.4: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e

http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Para as versões 1.0 e 1.1: Assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].

b) A partir da versão 1.2: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

## 5.2.2.2 Requisitos de Revogação

### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

### 5.2.3.1 Requisitos de Certificados

#### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 118 -->
<!-- START OF PAGE 119 -->

ICP Brasil

# Infraestrutura de Chaves Públicas Brasileira

a) para a versão 1.0, 1.1 e 1.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt.

b) para a versão 1.3 e 1.4: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

## 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Para as versões 1.0 e 1.1: Os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 1.2: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

5.2.3.2.1 Requisitos de Revogação para Certificados Finais
5.2.3.2.1.1 Mecanismos de Revogação para Certificados
LCR ou OCSP.

5.2.3.2.2 Requisitos de Revogação para Certificados de ACs
5.2.3.2.2.1 Mecanismos de Revogação para Certificados
LCR ou OCSP.

## 5.2.4 Conjunto de Restrições de Algoritmos

### 5.2.4.1 Restrições de Algoritmos para Signatário

5.2.4.1.1 Restrições de Algoritmos
5.2.4.1.1.1 Identificador de Algoritmo

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0, 1.1 e 1.2: sha256WithRSAEncryption(1.2.840.113549.1.1.11) ou sha512WithRSAEncryption(1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 119 -->
<!-- START OF PAGE 120 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

b) para a versão 1.3 e 1.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ouid-Ed448ph (1.3.101.115). (Redação dada pela Instrução Normativa ITI n° 34, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

## 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 2048 bits; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

b) para a versão 1.3 e 1.4: (Redação dada pela Instrução Normativa ITI n° 34, de 2025)

sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.

sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.

id-Ed25519 e id-Ed25519ph: 256 bits.

id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 120 -->
<!-- START OF PAGE 121 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 14 POLÍTICA-PADRÃO AD-RA BASEADA EM PADES

## 1 Identificador da Política de Assinatura

O nome desta Política de Assinatura para a versão 1.0 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO PDF, versão 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.14.1.

O nome desta Política de Assinatura para a versão 1.1 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO PDF, versão 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.14.1.1.

O nome desta Política de Assinatura para a versão 1.2 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO PDF, versão 1.2 e o seu Object Identifier (OID) é 2.16.76.1.7.1.14.1.2.

O nome desta Política de Assinatura para a versão 1.3 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO PDF, versão 1.3 e o seu Object Identifier (OID) é 2.16.76.1.7.1.14.1.3. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

O nome desta Política de Assinatura para a versão 1.4 é POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIAS PARA ARQUIVAMENTO NO FORMATO PDF, versão 1.4 e o seu Object Identifier (OID) é 2.16.76.1.7.1.14.1.4. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 2 Data de Emissão

A data de emissão de cada PA é:

a) para a versão 1.0: 25/08/2015;
b) para a versão 1.1: 15/07/2016;
c) para a versão 1.2: 14/05/2018; (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
d) para a versão 1.3: 12/06/2025; e (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
e) para a versão 1.4: 23/07/2025. (Incluído pela Instrução Normativa ITI nº 34, de 2025)

## 3 Nome da Entidade emissora da Política de Assinatura

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
120

<!-- END OF PAGE 121 -->
<!-- START OF PAGE 122 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

A entidade emissora desta PA é identificada pelo Distinguished Name “C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao – ITI”.

# 4 Campo de Aplicação

Este tipo de assinatura é adequado para aplicações que necessitam realizar o arquivamento do conteúdo digital assinado por longos períodos, sabendo-se que podem surgir fraquezas, vulnerabilidades ou exposição a fragilidades dos algoritmos, funções e chaves criptográficas utilizadas no processo de geração de assinatura digital.

Ele provê proteção contra fraqueza dos algoritmos, funções e tamanho de chaves criptográficas, desde que o carimbo do tempo de arquivamento seja realizado tempestivamente e utilize algoritmos, funções e tamanhos de chave considerados seguros no momento de sua geração.

Além disso, oferece segurança quanto à irretratabilidade, e permite que se verifique a validade da assinatura digital mesmo que ocorra comprometimento da chave privada da AC que emitiu o certificado do signatário (desde que o carimbo do tempo sobre as referências/valores dos certificados tenha sido colocado antes desse comprometimento).

Este tipo de PA é aplicável apenas em arquivos do tipo PDF.

# 5 Política de Validação da Assinatura

## 5.1 Período para Assinatura

Para a versão 1.0, o período para assinatura desta PA é de 25/08/2015 a 02/03/2029.
Para a versão 1.1, o período para assinatura desta PA é de 15/07/2016 a 02/03/2029.
Para a versão 1.2, o período para assinatura desta PA é de 14/05/2018 a 02/03/2029.
Para a versão 1.3, o período para assinatura desta PA é de 12/06/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)
Para a versão 1.4, o período para assinatura desta PA é de 23/07/2025 a 22/10/2037. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 5.2 Regras Comuns

### 5.2.1 Regras de Signatário e Verificador

#### 5.2.1.1 Regras do Signatário

##### 5.2.1.1.1 Dados Externos ou Internos a Assinatura

O conteúdo assinado deve ser externo à assinatura.

##### 5.2.1.1.2 Atributos ou Propriedades Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos assinados:

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 122 -->
<!-- START OF PAGE 123 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
www.icp-brasil.com.br

a) id-contentType;
b) id-messageDigest;
c) id-aa-signingCertificateV2;
d) id-aa-ets-sigPolicyId.

## 5.2.1.1.3 Atributos ou Propriedades Não-Assinados Obrigatórios

As assinaturas feitas segundo esta PA definem como obrigatórios os seguintes atributos não-assinados:

a) id-aa-signatureTimeStampToken.

## 5.2.1.1.4 Certificados Obrigatoriamente Referenciados

O atributo *id-aa-signingCertificateV2* deve conter referência apenas para o certificado do signatário.

## 5.2.1.1.5 Certificados Obrigatórios do Caminho de Certificação

Para a versão 1.0, 1.1, 1.2, 1.3 e 1.4: o certificado do signatário. (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

## 5.2.1.1.6 Regras Adicionais do Signatário

### 5.2.1.1.6.1 Extensão br_ext_mandatedPdfSigDicEntries.

### 5.2.1.1.6.1.1 Entradas obrigatórias do Dicionário de Assinaturas:

a) Type;
b) Filter;
c) SubFilter;
d) Contents;
e) ByteRange.

### 5.2.1.1.6.2 Extensão br_ext_dss

### 5.2.1.1.6.2.1 Entradas obrigatórias do campo dssDictionary

a) Type;
b) VRI;
c) Certs;
d) OCSPs ou CRLs (ValidationValues, anexo4);
e) PBAD_PolicyArtifacts;
f) PBAD_LpaArtifacts;
g) PBAD_LpaSignatures.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 123 -->
<!-- START OF PAGE 124 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 5.2.1.1.6.2.2 Entradas obrigatórias do campo vriDictionary

a) Type;
b) Cert;
c) OCSP ou CRL (ValidationValues, anexo4);
d) PBAD_PolicyArtifact;
e) PBAD_LpaArtifact;
f) PBAD_LpaSignature.

# 5.2.1.1.6.3 Extensão br_ext_mandatedDocTSEntries

Entradas obrigatórias do DocumentTimestamp:

a) Type;
b) SubFilter;
c) Contents.

# 5.2.1.2 Regras do Verificador

# 5.2.1.2.1 Atributos ou Propriedades Não-Assinados Obrigatórios

Caso não tenham sido incluídos pelo signatário, os seguintes atributos DEVEM ser incluídos pelo verificador:

a) id-aa-signatureTimeStampToken.

# 5.2.1.2.2 Regras Adicionais do Verificador

# 5.2.1.2.2.1 Extensão br_ext_dss

# 5.2.1.2.2.1.1 Entradas obrigatórias do campo dssDictionary

a) Type;
b) VRI;
c) Certs;
d) OCSPs ou CRLs (ValidationValues, anexo4);
e) PBAD_PolicyArtifacts;
f) PBAD_LpaArtifacts;
g) PBAD_LpaSignatures.

# 5.2.1.2.2.1.2 Entradas obrigatórias do campo vriDictionary

a) Type;
b) Cert;
c) OCSP ou CRL (ValidationValues, anexo4);

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1
123

<!-- END OF PAGE 124 -->
<!-- START OF PAGE 125 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

d) PBAD_PolicyArtifact;
e) PBAD_LpaArtifact;
f) PBAD_LpaSignature.

## 5.2.1.2.2.2 Extensão br_ext_mandatedDocTSEntries

Entradas obrigatórias do DocumentTimestamp:
a) Type;
b) SubFilter;
c) Contents.

## 5.2.2 Condições de Confiabilidade dos Certificados dos Signatários

### 5.2.2.1 Requisitos de Certificados

#### 5.2.2.1.1 Raiz Confiável

A validação deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0, 1.1 e 1.2:
http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt.

b) para a versão 1.3 e 1.4: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

#### 5.2.2.1.2 Conjunto de Políticas de Certificado Aceitável

a) Paras as versões 1.0 e 1.1: Assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04 [7].
b) A partir da versão 1.2: o conjunto de Políticas de Certificado Aceitável deve estar vazio.

### 5.2.2.2 Requisitos de Revogação

#### 5.2.2.2.1 Requisitos de Revogação para Certificados Finais

##### 5.2.2.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

#### 5.2.2.2.2 Requisitos de Revogação para Certificados de ACs

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 125 -->
<!-- START OF PAGE 126 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 5.2.2.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

# 5.2.3 Condições de Confiabilidade do Carimbo do Tempo

## 5.2.3.1 Requisitos de Certificados

### 5.2.3.1.1 Raiz Confiável

A validação da assinatura constante no carimbo do tempo deve ser feita tomando como ponto de confiança os certificados da AC Raiz da ICP-Brasil, disponíveis em:

a) para a versão 1.0, 1.1 e 1.2:

http://acraiz.icpbrasil.gov.br/ICP-Brasilv2.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt.

b) para a versão 1.3 e 1.4: (Redação dada pela Instrução Normativa ITI nº 34, de 2025)

http://acraiz.icpbrasil.gov.br/ICP-Brasilv5.crt e
http://acraiz.icpbrasil.gov.br/ICP-Brasilv12.crt.

### 5.2.3.1.2 Conjunto de Políticas de Certificado Aceitável

a) Paras as versões 1.0 e 1.1: os carimbos do tempo deverão ser criados com chave privada associada a certificados ICP-Brasil tipo T3 (do OID é 2.16.76.1.2.303.1 ao OID 2.16.76.1.2.303.100) ou T4 (do OID é 2.16.76.1.2.304.1 ao OID 2.16.76.1.2.304.100), conforme definido no DOC-ICP-04 [7].

b) A partir da versão 1.2: o conjunto de Políticas de Certificado Aceitável deve estar vazio. (Redação dada pela Instrução Normativa ITI nº 33, de 2025)

## 5.2.3.2 Requisitos de Revogação

### 5.2.3.2.1 Requisitos de Revogação para Certificados Finais

#### 5.2.3.2.1.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

### 5.2.3.2.2 Requisitos de Revogação para Certificados de ACs

#### 5.2.3.2.2.1 Mecanismos de Revogação para Certificados

LCR ou OCSP.

## 5.2.4 Conjunto de Restrições de Algoritmos

### 5.2.4.1 Restrições de Algoritmos para Signatário

#### 5.2.4.1.1 Restrições de Algoritmos

##### 5.2.4.1.1.1 Identificador de Algoritmo

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 126 -->
<!-- START OF PAGE 127 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

Os processos para criação e verificação de assinaturas segundo esta PA devem utilizar o algoritmo:

a) para a versão 1.0, 1.1 e 1.2: sha256WithRSAEncryption(1.2.840.113549.1.1.11) ou sha512WithRSAEncryption(1.2.840.113549.1.1.13); e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

b) para a versão 1.3 e 1.4: sha256WithRSAEncryption (1.2.840.113549.1.1.11); sha256WithECDSAEncryption (1.2.840.10045.4.3.2); sha512WithRSAEncryption (1.2.840.113549.1.1.13); sha512WithECDSAEncryption (1.2.840.10045.4.3.4); id-Ed25519 (1.3.101.112); id-Ed25519ph (1.3.101.114); id-Ed448 (1.3.101.113); ou id-Ed448ph (1.3.101.115). (Redação dada pela Instrução Normativa ITI n° 34, de 2025)

Nota: A ausência de previsão para as curvas id-Ed521 e id-Ed521ph deve-se a restrições técnicas. (Incluído pela Instrução Normativa ITI n° 33, de 2025)

## 5.2.4.1.1.2 Tamanho Mínimo de Chave

O tamanho mínimo de chave para criação de assinaturas segundo esta PA é de:

a) para a versão 1.0, 1.1 e 1.2: 2048 bits; e (Redação dada pela Instrução Normativa ITI n° 33, de 2025)

b) para a versão 1.3 e 1.4: (Redação dada pela Instrução Normativa ITI n° 34, de 2025)
sha256WithRSAEncryption e sha512WithRSAEncryption: 2048 bits.
sha256WithECDSAEncryption e sha512WithECDSAEncryption: 256 bits.
id-Ed25519 e id-Ed25519ph: 256 bits.
id-Ed448 e id-Ed448ph: 456 bits.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 127 -->
<!-- START OF PAGE 128 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

ANEXO 3

GERENCIAMENTO DE POLÍTICAS DE ASSINATURA NA ICP-BRASIL

1 INTRODUÇÃO

1.1 Na verificação da validade de uma Assinatura Digital ICP-Brasil diversos atributos e propriedades devem ser checados. É preciso verificar, por exemplo, se a assinatura contém apenas algoritmos e parâmetros permitidos pelas normas da ICP-Brasil.

1.2 Além disso, é necessário validar também se a assinatura foi criada com a utilização de uma Política de Assinatura (PA) aprovada pela AC Raiz da ICP-Brasil.

1.3 O objetivo do presente documento é introduzir regras claras e transparentes para determinar a validade das PAs aprovadas e definir processos de prorrogação e revogação de uma PA.

1.4 Para facilitar a verificação da validade de uma PA aprovada e para permitir a criação de sistemas que decidam de forma automatizada se uma determinada PA foi aprovada, a AC Raiz, além de publicá-la em seu repositório web, gera e assina digitalmente uma Lista de Políticas de Assinatura Aprovadas (LPA), contendo dados que identificam uma PA.

1.5 O formato da LPA e a forma de utilizá-la estão definidos no presente documento, bem como os procedimentos de administração de PAs aprovadas, o que inclui: a forma de publicação das PAs e os procedimentos a serem adotados em caso de término da validade, prorrogação da validade e revogação de PAs aprovadas.

2 ADMINISTRAÇÃO E CICLO DE VIDA DE UMA PA

2.1 PAs aprovadas são gerenciadas pela AC Raiz da ICP-Brasil com base neste documento.

2.2 Uma Política de Assinatura passa pelas seguintes etapas de vida:

a) criação;
b) aprovação;
c) publicação;
d) expiração (se for o caso);
e) prorrogação de validade (se for o caso);
f) revogação (se for o caso).

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 128 -->
<!-- START OF PAGE 129 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

# 3 APROVAÇÃO DE UMA PA

As PAs aprovadas pela AC Raiz devem ser submetidas à avaliação prévia do CG-ICP-Brasil.

# 4 PUBLICAÇÃO DA PA E DA LPA

4.1 Os arquivos com as PAs aprovadas são publicados no repositório da AC Raiz da ICP-Brasil e são utilizados para a criação da LPA.

4.2 As LPAs são assinadas e publicadas pela AC Raiz da ICP-Brasil, de forma segura, no seu repositório no seguinte endereço web:

https://www.gov.br/iti/pt-br/assuntos/repositorio/lista-de-politicas-de-assinatura

4.3 As LPAs são atualizadas pela AC Raiz pelo prazo máximo de 90 dias e contêm em seus corpos a data da sua próxima atualização.

4.4 As LPAs são assinadas com Assinaturas Digitais ICP-Brasil, utilizando PKCS #7 para CAdES e PAdES e XMLDSig para XAdES, todas assinadas por um certificado de pessoa jurídica do ITI, emitido por uma das autoridades certificadoras credenciadas na ICP-Brasil.

4.5 As LPAs são codificadas em linguagem de máquina (ASN.1 e XML) e trazem, para cada PA aprovada, os seguintes dados:

a) período de validade da Política;
b) data de revogação, se for o caso;
c) URLs da PA em formato processável por máquina (XML/DER);
d) resumos criptográficos dos arquivos da PA, processável por máquina (XML/DER);
e) assinatura digital PKCS #7 para o formato ASN.1 e XMLdSIG para o formato XML;
f) Identificador da política de assinatura;

4.6 PAs aprovadas são válidas pelo período indicado no campo de período para assinatura se ela não tiver sido revogada.

# 5 PRORROGAÇÃO DA VALIDADE DE UMA PA APROVADA

5.1 A validade de uma PA pode ser prorrogada desde que não tenham sido encontradas fragilidades na PA, as quais não sejam tecnicamente aceitáveis para o novo período de validade.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 129 -->
<!-- START OF PAGE 130 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

5.2 A prorrogação feita por meio da publicação de uma nova versão da PA contendo os dados alterados sobre data de publicação, começo e término da validade da PA. A publicação é feita utilizando os procedimentos citados no capítulo anterior.

# 6 REVOGAÇÃO DE UMA PA

6.1 PAs aprovadas PODEM ser revogadas pela AC Raiz da ICP-Brasil a qualquer tempo, a partir da emissão de uma nova LPA na qual o campo “data de revogação”, relativo àquela PA esteja atualizado com a data da emissão da LPA.

# 7 PROCEDIMENTOS PARA CRIAÇÃO E VERIFICAÇÃO DA LPA

7.1 A estrutura do arquivo LPA é a seguinte:

a) identificador da política de assinatura;
b) campo **PERÍODO PARA ASSINATURA**: contém a datas de início e de final do período de validade da PA;
c) campo **DATA DE REVOGAÇÃO**: contém a data de revogação da PA, se for o caso;
d) campo **URL MÁQUINA**: contém a URL do repositório da AC Raiz da ICP-Brasil em que está publicada a PA aprovada, em formato DER ou XML;
e) campo **RESUMO CRIPTOGRÁFICO MÁQUINA**: contém o resumo criptográfico da PA codificada em DER ou XML;
f) assinatura digital PKCS #7 para o formato ASN.1 e XMLDSig para o formato XML.

7.2 A LPA contém as PAs aprovadas vigentes, expiradas e revogadas, característica esta necessária à verificação de Assinaturas Digitais ICP-Brasil criadas no passado por meio de PAs aprovadas que tenham sido válidas por um período, mas que posteriormente tenham expirado ou sido revogadas.

7.3 A LPA DEVE ser verificada em relação ao momento atual, validando-se a assinatura da LPA assim como o certificado do signatário da LPA.

7.4 Codificação de especificações da LPA

A codificação ASN.1 e o esquema XML da LPA podem ser obtidos no repositório do Instituto Nacional de Tecnologia da Informação, mantido em:

https://www.gov.br/iti/pt-br/assuntos/repositorio

Os artefatos também podem ser acessados diretamente pelo link:

https://www.gov.br/iti/pt-br/assuntos/repositorio/artefatos-de-assinatura-digital

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 130 -->
<!-- START OF PAGE 131 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira
A

# ANEXO 4

# EXTENSÕES DE POLÍTICAS DE ASSINATURA PARA PAdes

## 1 INTRODUÇÃO

Para que a estrutura das PAs, descrita em [1] consiga apontar os campos da estrutura do PDF é necessário expandir essa estrutura. Essa expansão é feita através da descrição de novas extensões de PA, conforme o item 6.11 de [1]. Essas extensões servirão como guia de implementação dos dicionários PDF utilizados para criar uma assinatura PAdes.

Estas extensões deverão ser adicionadas no campo de extensões (signPolExtensions) das regras do signatário (item 6.5.1 de [1]) e no campo de extensões (signPolExtensions) das regras do verificador (item 6.5.2 de [1]).

## 2 EXTENSÕES

### 2.1 DICIONÁRIO DE ASSINATURA

Essa extensão tem função similar à tabela de atributos assinados obrigatórios. Nela constarão todas as entradas obrigatórias e, opcionalmente, seu valor que deverá constar na assinatura.

#### 2.1.1 SINTAXE ASN.1

```text
br-ext-mandatedPdfSigDicEntries  OBJECT IDENTIFIER ::= { 2.16.76.1.8.1 }
```

```text
MandatedPdfSigDicEntries ::= SEQUENCE OF PdfEntry
```

```text
PdfEntry ::= SEQUENCE {
id     UTF8String (SIZE (1..MAX)),
value     OCTET STRING OPTIONAL -- contém a codificação DER do conteúdo obrigatório da entrada
}
```

O campo MandatedPdfSigDicEntries representa a lista de entradas obrigatórias que uma assinatura deverá ter no dicionário de assinaturas. Esse campo é formado por uma lista de entradas PDF, representadas pela estrutura PdfEntry. O PdfEntry, por sua vez, traz o nome da entrada PDF que deverá constar no dicionário e, opcionalmente, o valor que deverá ser empregado nessa entrada. Tal valor será codificado em DER de acordo com o tipo da entrada identificada por “id”. A tabela A.4.3 apresenta as entradas obrigatórias e a formatação do valor.

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 131 -->
<!-- START OF PAGE 132 -->

ICP Brasil
Infraestrutura de Chaves Públicas Brasileira

# 2.2 DICIONÁRIO DOCUMENT SECURITY STORE (DSS)

Quando esta extensão estiver presente, ela indicará que o DSS DEVE ser codificado na assinatura. As entradas indicadas por essa extensão serão consideradas obrigatórias.

# 2.2.1 SINTAXE ASN.1

```txt
br-ext-dss OBJECT IDENTIFIER ::= { 2.16.76.1.8.2 }
DssDictionary ::= SEQUENCE{
mandatedEntries SEQUENCE OF PdfEntry,
vriMandatedEntries SEQUENCE OF PdfEntry OPTIONAL
}
```

O campo DssDictionary representa o dicionário DSS, descrito em ETSI PAdES-LTV [9]. Esse campo é formado por uma lista de entradas obrigatórias no dicionário DSS e pelo campo vriDictionary, que é a indicação do uso do dicionário Validation Related Information (VRI) [9].

O campo VriDictionary apresenta quais entradas do dicionário VRI são obrigatórias para cada assinatura que usá-lo.

# 2.3 DICIONÁRIO DOCUMENT TIME-STAMP

Define os campos obrigatórios do carimbo do tempo do documento, que é inserido como uma assinatura a parte no PDF. As entradas presentes nessa extensão são obrigatórias.

# 2.3.1 SINTAXE ASN.1

```txt
br-ext-mandatedDocTSEntries OBJECT IDENTIFIER ::= { 2.16.76.1.8.3 }
MandatedDocTSEntries ::= SEQUENCE OF PdfEntry
```

O campo mandatedDocTSEntries apresenta uma lista de entradas para o dicionário do carimbo do tempo do documento, ou Document Timestamp, que é um dicionário similar ao dicionário de assinaturas, mas a entrada Contents possui um carimbo do tempo ao invés de uma assinatura tradicional.

# 2.4 Artefatos de PA e LPA na estrutura PDF

A indicação da codificação dos artefatos de políticas de assinatura (PA, LPA e assinatura da LPA) será formada por 3 entradas no Document Time-stamp. Essas entradas funcionarão de

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 132 -->
<!-- START OF PAGE 133 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

forma parecida com a codificação dos certificados, LCRs e OCSPs presentes no DSS. Ou seja, serão referências indiretas aos respectivos objetos codificados em BER.

Tabela A.4.1 – Entradas adicionais do dicionário Document Security Store.

|  ENTRADA | TIPO | VALOR  |
| --- | --- | --- |
|  PBAD_PolicyArtifacts | Referência | Uma referência para o objeto PDF que contém as PAs codificadas em BER. Essa entrada contém as políticas de assinatura que devem ser usadas para a validação das assinaturas contidas no documento PDF  |
|  PBAD_LpaArtifacts | Referência | Uma referência para o objeto PDF que contém as LPAs codificadas em BER. Essa entrada contém as LPAs que devem ser usadas para validar as políticas de assinatura usadas nas assinaturas contidas no documento PDF  |
|  PBAD_LpaSignatures | Referência | Uma referência para o objeto PDF que contém as assinaturas das LPAs.  |

A Tabela A.4.1 descreve as entradas a serem adicionadas ao DSS, descrito em [9]. Essas entradas guardam todos os dados necessários para validar uma política de assinatura localmente. A entrada PBAD_PolicyArtifacts e PBAD_LpaArtifacts são arrays de objetos indiretos (ver ISO 32000-1) contendo todas as PAs e LPAs, respectivamente, utilizadas no documento PDF assinado no padrão PAdES. A entrada PBAD_LpaSignatures é um array de objetos indiretos contendo as assinaturas das LPAs incluídas na entrada PBAD_LpaArtifacts.

Tabela A.4.2 – Entradas adicionais do dicionário VRI.

|  ENTRADA | TIPO | VALOR  |
| --- | --- | --- |
|  PBAD_PolicyArtifact | Referência | Uma referência para o objeto PDF que contém uma PA codificada em BER. Essa entrada contém a política de assinatura que deve ser usada para a validação da assinatura  |
|  PBAD_LpaArtifact | Referência | Uma referência para o objeto PDF que contém uma LPA codificada em BER. Essa entrada contém a LPA que deve ser usada para validar a política de assinatura usada na assinatura  |
|  PBAD_LpaSignature | Referência | Uma referência para o objeto PDF que contém a assinatura da LPA.  |

A Tabela A.4.2 descreve as entradas a serem adicionadas no dicionário VRI, descrito em ETSI PAdES-LTV [9]. Essas entradas adicionais servem para indicar qual PA e qual LPA devem ser utilizadas na validação da assinatura à qual determinado VRI faz referência. A entrada PaArtifact deve conter um objeto indireto à PA utilizada para realizar a assinatura. A entrada LpaArtifact deve conter um objeto indireto à LPA vigente durante o período de

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 133 -->
<!-- START OF PAGE 134 -->

ICP Brasil

Infraestrutura de Chaves Públicas Brasileira

realização da assinatura. A entrada LpaSignature deve conter a assinatura da LPA.

## 2.5 Relação dos tipos de PdfEntry

Definição em ASN.1 dos valores de cada tipo de entrada de dicionário. As entradas não descritas aqui não possuem um valor fixo aplicável, portanto, dispensa a codificação de um valor. Sua presença indica sua obrigatoriedade.

Tabela A.4.3 - Sintaxe ASN.1 por tipos de entradas.

|  Entrada (id) | Sintaxe ASN.1 (value)  |
| --- | --- |
|  Type | UTF8String (SIZE (1..MAX))  |
|  Filter | UTF8String (SIZE (1..MAX))  |
|  SubFilter | UTF8String (SIZE (1..MAX))  |
|  ValidationValues | ValidationReq  |

A entrada de dicionário ValidationValues, não reflete a uma entrada do DSS ou VRI de fato, mas indica qual tipo de artefato de revogação deve ser incluído nessas estruturas. Essa estrutura pode indicar se um DSS ou VRI deve conter apenas LCR, apenas OCSP, qualquer um dos dois ou obrigatoriamente os dois.

```
ValidationReq ::= ENUMERATED {
crlsOnly (0), -- indica que apenas a entrada CRLs/CRL pode ser usada
ocpssOnly (1), -- indica que apenas a entrada OCSPs/OCSP pode ser usada
either (2), -- indica que podem ser usadas LCRs/LCR ou OCSPs/OCSP no DSS/VRI
both (3) -- indica que devem ser usadas LCRs/LCR e OCSPs/OCSP no DSS/VRI
}
```

## 2.6 Codificação de especificações ASN.1

A codificação ASN.1 das extensões de Políticas de Assinatura para PAdES podem ser obtidas no repositório do Instituto Nacional de Tecnologia da Informação, mantido em:

https://www.gov.br/iti/pt-br/assuntos/repositorio

Os artefatos também podem ser acessados diretamente pelo link:

https://www.gov.br/iti/pt-br/assuntos/repositorio/codificacao-de-especificacoes-ce

Requisitos das Políticas de Assinatura Digital na ICP-Brasil – DOC-ICP-15.03 v.9.1

<!-- END OF PAGE 134 -->
