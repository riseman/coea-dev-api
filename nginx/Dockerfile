FROM nginx

# Обновление списка пакетов и установка зависимостей
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gnupg2 \
    libpcre3 \
    libpcre3-dev \
    libxslt-dev \
    libxml2-dev \
    libssl-dev \
    zlib1g-dev

# Копирование директории с исходным кодом NJS внутрь контейнера
COPY njs /usr/src/njs

# Получение исходного кода NGINX (используем latest для последней версии)
WORKDIR /usr/src
RUN curl -LO http://nginx.org/download/nginx-1.24.0.tar.gz
RUN tar -xvzf nginx-1.24.0.tar.gz

# Переход в директорию NGINX
WORKDIR /usr/src/nginx-1.24.0

# Конфигурация NGINX с модулем JavaScript
RUN ./configure --with-compat --with-ld-opt='-lpcre' --add-module=../njs/nginx
RUN make && make install



# Порт, который будет открыт контейнером
EXPOSE 80

# Команда запуска NGINX
CMD ["nginx", "-g", "daemon off;"]
