# Red team round 3: Symfony 7.1 micro kernel + traffic-twin PHP SDK
# (SymfonySubscriber in the request, tt-shipper as the long-running process).
# Served by the PHP built-in server (cli-server SAPI); PHP-FPM is not covered.
# Build (context = repository root, for sdk/php): test/redteam/frameworks/build_images.sh php
FROM composer:2.8.3 AS composer

FROM php:8.3-cli
RUN docker-php-ext-install pcntl >/dev/null
COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY sdk/php /sdk-php
WORKDIR /app
COPY test/redteam/frameworks/php/composer.json ./
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends unzip >/dev/null && rm -rf /var/lib/apt/lists/* \
 && COMPOSER_ALLOW_SUPERUSER=1 composer install -q --no-dev --no-interaction --no-progress --prefer-dist
COPY test/redteam/frameworks/php/src ./src
COPY test/redteam/frameworks/php/public ./public
COPY test/redteam/frameworks/php/start.sh /start.sh
RUN COMPOSER_ALLOW_SUPERUSER=1 composer dump-autoload -q --optimize --no-dev \
 && useradd -m -u 10001 app && install -d -o app -g app -m 0700 /var/lib/tt-state \
 && install -d -o app -g app /app/var && chmod 0755 /start.sh
USER app
EXPOSE 8080
CMD ["/start.sh"]
