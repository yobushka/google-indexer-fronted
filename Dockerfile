FROM nginx:latest

# Копируем приложение в контейнер
COPY . /usr/share/nginx/html

# Разрешаем доступ к service-account.json
RUN chown -R nginx:nginx /usr/share/nginx/html

EXPOSE 80
