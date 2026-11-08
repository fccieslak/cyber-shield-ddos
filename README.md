# Detecção precoce de ataques DDoS com IA em planos de dados programáveis

Projeto Cyber Shield

## Projeto

Os ataques distribuídos de negação de serviço (DDoS) estão cada vez mais frequentes e intensos. A defesa tradicional costuma enviar o tráfego a servidores de segurança fora do caminho da rede, o que atrasa a detecção e sobrecarrega esses servidores.

Os switches programáveis em P4 permitem inspecionar os pacotes na própria rede, em velocidade de linha, e agir antes de o ataque chegar ao serviço. O desafio é que esses dispositivos têm pouca memória e suportam poucas operações aritméticas, o que dificulta rodar modelos de inteligência artificial dentro deles.

Este projeto investiga como levar a detecção de DDoS para dentro do plano de dados, usando modelos leves de aprendizado de máquina que respeitem essas restrições.

## Objetivo

Investigar, desenvolver e avaliar protótipos de mecanismos leves de detecção precoce de DDoS baseados em aprendizado de máquina, operando integralmente em um ambiente emulado de redes programáveis (Mininet e switch BMv2).

Para isso, o trabalho busca responder a três perguntas:

- Quais atributos do tráfego distinguem um ataque do tráfego normal e podem ser calculados dentro de um switch?
- Quais modelos simples, como árvores de decisão e Random Forest, mantêm boa acurácia com poucos recursos?
- Como traduzir o modelo treinado para as estruturas do P4, como tabelas match-action e registradores?

O treinamento usa bases públicas de tráfego com ataques DDoS, como CIC e CAIDA. O desempenho é medido pela viabilidade da implementação no switch e pela acurácia, precisão, recall e F1 na classificação do tráfego malicioso.

Análises iniciais dos dados em `exploracao/`.
