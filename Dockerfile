FROM php:8.2-apache

# Устанавливаем необходимые зависимости
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    && docker-php-ext-install openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Копируем приложение в контейнер
COPY . /var/www/html/

# Разрешаем доступ к service-account.json
RUN chown -R www-data:www-data /var/www/html

# Включаем отображение ошибок для отладки
RUN echo "display_errors=On\nerror_reporting=E_ALL" > /usr/local/etc/php/conf.d/errors.ini

EXPOSE 80
