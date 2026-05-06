# Políticas CAdES ICP-Brasil

Este documento descreve como cada política CAdES ICP-Brasil deve ser montada no `signer-engine`: quais atributos entram, de onde vêm os dados, como o DER é codificado e quais normas justificam cada decisão.

Ele deve ser mantido como documentação viva. Ao adicionarmos AD-RC, AD-RA ou ajustes de interoperabilidade com ITI, acrescentamos novas seções sem reescrever o modelo inteiro.

## Referências

- DOC-ICP-15.03 v9.1: requisitos de geração/verificação e tabelas de atributos por política.
- DOC-ICP-04.01: atribuição de OIDs ICP-Brasil.
- RFC 5652: CMS `SignedData`, `SignerInfo`, atributos assinados e não assinados.
- RFC 5035: `signingCertificateV2`.
- RFC 5126: atributos CAdES como `signature-policy-identifier`, `certificateRefs`, `revocationRefs`, `escTimeStamp`.
- RFC 3161: `TimeStampReq`, `TimeStampResp` e `TimeStampToken`.
- RFC 5280: certificados X.509, CRL Distribution Points, Authority Information Access e CRLs.
- ETSI TR 102 272: formato ASN.1 de políticas de assinatura.

Ver também `docs/references.md`.

## Modelo Geral

Todas as assinaturas CAdES são CMS `SignedData`.

O `cms.Builder` sempre monta os atributos CMS básicos:

- `contentType`
- `messageDigest`

O `cades.Signer` sempre acrescenta:

- `signingTime`

A política CAdES acrescenta os atributos específicos do nível:

- atributos assinados via `Policy.SignedAttributes(ctx)`;
- atributos não assinados via `Policy.UnsignedAttributeNames()`.

O `SigningContext` contém dados dinâmicos usados pelas políticas:

- certificado assinante;
- cadeia de certificados;
- algoritmo de hash;
- modo attached/detached.

## Codificação de Atributos

Cada atributo CMS é codificado como:

```asn1
Attribute ::= SEQUENCE {
  attrType   OBJECT IDENTIFIER,
  attrValues SET OF AttributeValue
}
```

O valor interno de cada atributo CAdES é previamente serializado em DER e colocado como `RawValue` dentro de `attrValues`.

Para o input de `escTimeStamp`, usamos a concatenação definida para CAdES-C:

```text
signatureValue
|| signatureTimeStampToken attribute bytes
|| certificateRefs attribute bytes
|| revocationRefs attribute bytes
```

Onde cada atributo anterior entra como:

```text
DER(OID) || DER(SET OF attrValues)
```

## AD-RB

Nome no código:

```text
PA_AD_RB_v2_4
```

OID:

```text
2.16.76.1.7.1.1.2.4
```

URI da política:

```text
http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.der
```

Hash da política:

```text
1f3c904c44c392feef447e21faa7a04e85d9c0153346320f557b7042af5dcf13
```

### Atributos Assinados

AD-RB deve conter:

- `signingTime`
- `signingCertificateV2`
- `signature-policy-identifier`

`signingTime` é global do `cades.Signer`, não específico da política.

`signingCertificateV2` é montado a partir do certificado assinante:

- calcula `SHA-256(cert.Raw)`;
- cria `SigningCertificateV2`;
- inclui `ESSCertIDv2.CertHash`.

`signature-policy-identifier` é montado a partir dos metadados da política:

- OID da política;
- hash SHA-256 da política;
- URI da política como qualificador `id-spq-ets-uri`.

### Atributos Não Assinados

AD-RB não exige atributos CAdES não assinados.

## AD-RT

Nome no código:

```text
PA_AD_RT_v2_4
```

OID:

```text
2.16.76.1.7.1.2.2.4
```

URI da política:

```text
http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_4.der
```

Hash da política:

```text
fa59dca6d9c0e808eb7397b2de800cce5b0e4da2c42e2e5ef2496a2ce6badcb7
```

### Atributos Assinados

AD-RT herda os atributos assinados da AD-RB:

- `signingTime`
- `signingCertificateV2`
- `signature-policy-identifier`

### Atributos Não Assinados

AD-RT acrescenta:

- `signatureTimeStampToken`

O token é obtido por uma ACT/TSA via RFC 3161.

Fluxo:

1. O `cms.Builder` calcula e assina os atributos assinados.
2. O resultado da assinatura (`SignerInfo.Signature`) é passado para o builder de atributos não assinados.
3. O `TimeStampProvider` recebe:
   - bytes da assinatura;
   - algoritmo de hash da assinatura.
4. O provider monta `TimeStampReq` RFC 3161.
5. A ACT retorna um `TimeStampResp`.
6. Extraímos o `TimeStampToken` CMS.
7. O token DER é colocado no atributo `id-aa-signatureTimeStampToken`.

No caso atual, o provider Serpro faz:

- requisição OAuth client credentials;
- requisição RFC 3161 para o endpoint de carimbo;
- valida status do `TimeStampResp`;
- retorna apenas o token CMS DER.

## AD-RV

Nome no código:

```text
PA_AD_RV_v2_4
```

OID:

```text
2.16.76.1.7.1.3.2.4
```

URI da política:

```text
http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_4.der
```

Hash da política:

```text
ac8d3299189a58f88ec938d1b5918f65bd9d1b22e1d1a32b998f3fdf07ec3342
```

### Atributos Assinados

AD-RV herda os atributos assinados da AD-RB:

- `signingTime`
- `signingCertificateV2`
- `signature-policy-identifier`

### Atributos Não Assinados

AD-RV acrescenta, nesta ordem:

- `signatureTimeStampToken`
- `certificateRefs`
- `revocationRefs`
- `escTimeStamp`

A ordem é relevante porque `escTimeStamp` é calculado sobre a assinatura e os atributos não assinados anteriores.

## AD-RV: `certificateRefs`

OID:

```text
1.2.840.113549.1.9.16.2.21
```

Estrutura:

```asn1
CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
```

No nosso fluxo, `certificateRefs` referencia a cadeia de validação, sem o certificado assinante principal. Para timestamps, o mesmo princípio é aplicado: a cadeia da TSA entra em `certificateRefs`, mas o certificado assinante do token não entra nessa lista.

Cada `OtherCertID` contém:

- hash SHA-256 do certificado referenciado;
- `IssuerSerial` do certificado referenciado.

Detalhe importante de interoperabilidade:

- O `AlgorithmIdentifier` de SHA-256 em `OtherHashAlgAndValue` é serializado sem `NULL`;
- isto é necessário para compatibilidade com validadores estritos como o ITI.

## AD-RV: `revocationRefs`

OID:

```text
1.2.840.113549.1.9.16.2.22
```

Estrutura:

```asn1
CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef

CrlOcspRef ::= SEQUENCE {
  crlids    [0] CRLListID OPTIONAL,
  ocspids   [1] OcspListID OPTIONAL,
  otherRev  [2] OtherRevRefs OPTIONAL
}
```

Neste momento usamos apenas LCR/CRL, não OCSP. Isso atende a regra normativa "LCR ou OCSP".

Cada CRL é codificada como um `CrlOcspRef` separado:

```text
CompleteRevocationRefs
  CrlOcspRef { crlids [0] { uma CRL } }
  CrlOcspRef { crlids [0] { uma CRL } }
  ...
```

Isso segue o formato usado pelo `zapsign` e foi necessário para interoperabilidade com o ITI.

Cada `CrlValidatedID` contém:

- hash SHA-256 da CRL;
- `CrlIdentifier`, com:
  - issuer da CRL;
  - `thisUpdate`;
  - `crlNumber`, quando presente.

Validações feitas antes de aceitar uma CRL:

- `thisUpdate` não pode estar no futuro;
- `nextUpdate` precisa existir;
- `nextUpdate` precisa estar no futuro;
- a assinatura da CRL precisa validar com o certificado emissor;
- CRLs duplicadas são removidas por DER.

## AD-RV: Busca de CRL

As CRLs são buscadas a partir do certificado que precisa de referência de revogação.

Fonte primária:

```go
cert.CRLDistributionPoints
```

Fluxo:

1. Para cada certificado alvo, localiza o emissor na cadeia.
2. Para cada URL em `CRLDistributionPoints`, tenta baixar a CRL.
3. Aceita CRL DER ou PEM.
4. Valida assinatura e janela temporal.
5. Salva em cache.

Cache:

```text
internal/validation/crl-cache/
```

O nome do arquivo é `SHA-256(URL).crl`.

Antes de usar uma CRL cacheada:

- parseia novamente;
- valida assinatura com o emissor correto;
- valida `thisUpdate` e `nextUpdate`;
- remove o cache se estiver corrompido ou expirado.

## AD-RV: Descoberta de Cadeia via AIA

Nem todo token RFC 3161 traz a cadeia completa da TSA. O caso da SERPRO/ACT pode trazer o certificado assinante do timestamp e apontar o emissor via AIA.

Por isso o `CRLProvider` completa a cadeia antes de montar refs usando:

```go
cert.IssuingCertificateURL
```

Fluxo:

1. Verifica se o emissor do certificado já está na cadeia.
2. Se não estiver, baixa certificados pelas URLs de AIA.
3. Aceita certificado DER, PEM ou CMS/P7B.
4. Inclui apenas certificados CA.
5. Repete por profundidade limitada até completar a cadeia ou chegar em raiz autoassinada.

Isso foi necessário para montar refs da TSA quando o token RFC 3161 não trouxe toda a cadeia.

## AD-RV: Enriquecimento dos Tokens RFC 3161

AD-RV exige material de validação não apenas do assinante principal, mas também dos carimbos usados na assinatura.

Por isso enriquecemos os tokens RFC 3161:

- `signatureTimeStampToken`
- `escTimeStamp`

Cada token é um CMS `SignedData`. O certificado assinante do token e a cadeia da TSA são extraídos do próprio token, ou completados via AIA pelo `CRLProvider`.

Depois o `SignerInfo` interno do token recebe:

- `certificateRefs`
- `revocationRefs`

Esses atributos são não assinados dentro do token. Portanto, adicioná-los não invalida a assinatura do carimbo, pois `UnsignedAttrs` não fazem parte do conteúdo assinado pelo `SignerInfo`.

O arquivo AD-RV válido passa a conter refs em três níveis:

- refs do CMS externo;
- refs dentro de `signatureTimeStampToken`;
- refs dentro de `escTimeStamp`.

Essa diferença foi decisiva para validação no ITI.

## AD-RV: `escTimeStamp`

OID:

```text
1.2.840.113549.1.9.16.2.25
```

O `escTimeStamp` é um carimbo RFC 3161 calculado sobre:

```text
signatureValue
|| signatureTimeStampToken
|| certificateRefs
|| revocationRefs
```

No código, o input é montado por `EscTimeStampInput`:

- exige assinatura não vazia;
- exige atributos anteriores não vazios;
- serializa cada atributo como `OID DER || SET OF attrValues DER`;
- concatena tudo na ordem em que os atributos foram montados.

Depois:

1. O `TimeStampProvider` carimba esse input.
2. O token RFC 3161 retornado também é enriquecido com refs da TSA.
3. O token enriquecido é colocado em `id-aa-ets-escTimeStamp`.

## Ordem Atual da AD-RV

Ordem declarada na política:

```text
signatureTimeStampToken
certificateRefs
revocationRefs
escTimeStamp
```

Motivo:

- `signatureTimeStampToken` precisa existir antes dos refs, porque seus certificados da TSA são usados nos refs externos.
- `certificateRefs` e `revocationRefs` precisam existir antes do `escTimeStamp`, porque entram no input do `escTimeStamp`.
- `escTimeStamp` precisa ser o último desses atributos.

## Próximas Políticas

As próximas seções devem ser adicionadas quando implementarmos:

- AD-RC: incluir `certificateValues` e `revocationValues`;
- AD-RA: incluir material de arquivamento, como `archiveTimeStampV2`;
- suporte OCSP: adicionar `ocspids` em `CompleteRevocationRefs`, mantendo CRL como opção válida;
- regras específicas para PAdES/XAdES, se compartilharem providers de validação.
