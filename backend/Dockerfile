# Base PHP com Apache
FROM php:8.2-apache

# Atualizar pacotes e instalar extensões necessárias
RUN apt-get update && apt-get install -y \
    libzip-dev zip unzip \
    && docker-php-ext-install pdo_mysql

# Configurar permissões corretas no diretório HTML
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Copiar os arquivos do backend para o contêiner
COPY . /var/www/html

# Expor a porta 80
EXPOSE 80

# Habilitar logs em tempo real para o Apache
RUN ln -sf /dev/stdout /var/log/apache2/access.log \
    && ln -sf /dev/stderr /var/log/apache2/error.log
