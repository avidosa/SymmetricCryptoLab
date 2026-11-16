FROM node:24-slim
# el usuario por defecto de la imagen (node) ocupa el uid 1000; uso uno propio para el prompt
RUN useradd -m -u 1001 analista
USER analista
ENV PS1="analista@cripto-lab:\\w$ "
